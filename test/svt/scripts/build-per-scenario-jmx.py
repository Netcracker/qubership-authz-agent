#!/usr/bin/env python3

# Copyright 2024-2026 Netcracker Technology Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Generator for the 28 per-scenario JMX plans + per-RPS directories.

Reads the shared scenario inventory from `build-per-scenario-seeds.py`
and emits, deterministically:

  - tests/svt/load-tests/per-scenario/<scenario>/test.jmx
  - tests/svt/load-tests/per-scenario/<scenario>/<rps>rps/scenario.md
  - tests/svt/load-tests/per-scenario/<scenario>/<rps>rps/config.env
  - tests/svt/load-tests/per-scenario/<scenario>/<rps>rps/run
  - tests/svt/load-tests/per-scenario/<scenario>/<rps>rps/artifacts/.gitkeep
  - tests/svt/load-tests/per-scenario/<scenario>/artifacts/.gitkeep

Layout mirrors `tests/svt/load-tests/full/mixed/100rps/` and
`tests/svt/load-tests/mixed-flow/100rps/`. Each JMX is a single-thread
group plan with a `${MODE}` switch wired into a `JSR223PreProcessor`
that builds the request body verbatim from the profiler scenario shape
(canonical → `/access/v1/authorize`, legacy → the scenario's
compatibility endpoint).

The 28 scenario × 6 RPS layout is 168 sub-directories. Each per-RPS
`run` is a standalone wrapper that sources `svt-lib.sh`, restarts OPA,
and invokes the shared per-scenario JMX at the per-directory
`TARGET_RPS`. The sweep harness (`tests/svt/scripts/per-scenario-decision-time`)
invokes the same `run` files in order.

Run from the authz-agent repo root:

    tests/svt/scripts/build-per-scenario-jmx.py

Deterministic — re-running yields a byte-for-byte identical output.
"""

from __future__ import annotations

import importlib.util
import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
SVT_DIR = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))
LOAD_TESTS_ROOT = os.path.join(SVT_DIR, "load-tests", "per-scenario")
SEEDS_PATH = os.path.join(SCRIPT_DIR, "build-per-scenario-seeds.py")

RPS_LEVELS = (100, 200, 300, 400, 500, 1000)

# Per-RPS thread count. We budget ~10 threads per 100 RPS. The
# single-thread-group plan must absorb the full target RPS, so this
# is generous — `ConstantThroughputTimer` still caps the actual rate
# and threads only set the parallelism ceiling for high-latency
# scenarios (bulk-1000 averages ~60 ms per request → ~60 concurrent
# requests at 1000 RPS).
#
# Tried the lower 5/10/.../50 budget (mirroring mixed-flow per-TG)
# on 2026-05-19; achieved RPS dropped 949 → 890 and avg latency
# doubled on `ols-single @ 1000 RPS`. ConstantThroughputTimer at
# `calcMode=2` (per-active-thread share) requires enough threads to
# disperse the rate evenly across the wall-clock window — at 50
# threads × 1000 RPS = 20 RPS/thread quantum 50 ms, the rate becomes
# bursty when individual responses are sub-millisecond.
THREADS_FOR_RPS = {100: 10, 200: 20, 300: 30, 400: 40, 500: 50, 1000: 100}

# D-20 (2026-05-18 refinement): load window is 15 s with 3 s ramp.
# Mixed-flow defaults (60 s / 5 s) would push the 336-run sweep to
# ~10–12 h per mode; 15 s + 3 s ramp keeps ~12 s of steady-state
# while compressing the full canonical + legacy budget to ~2–3 h.
RAMP_SECONDS = 3
DURATION_SECONDS = 15


def _load_inventory():
    spec = importlib.util.spec_from_file_location("seeds_mod", SEEDS_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def _write_text(path: str, content: str, *, make_executable: bool = False) -> None:
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    if make_executable:
        mode = os.stat(path).st_mode | 0o111
        os.chmod(path, mode)


# ── per-scenario Groovy body builders ─────────────────────────────────────
#
# Each builder emits a Groovy preprocessor that switches on the `mode`
# JMeter property and sets `req_path` / `req_body` / `body_raw`:
#
#   - canonical  → POST /access/v1/authorize on Envoy
#   - legacy     → POST <scenario.legacy_endpoint> on Envoy
#   - opa-direct → POST /v1/data/authorize on OPA (port 8181 via
#                  the bridged `jmeter` compose service — OPA's port is
#                  NOT exposed to the host, see docker-compose.yml).
#
# The opa-direct body wraps the canonical decision input in `{"input":
# {...}}` and adds `authorizationToken` / `authorizationType` /
# `requestHeaders` / `decisionLogPipTrace`, matching the shape proven by
# tests/svt/load-tests/opa-direct/mixed/1000rps/test.jmx. For header-PIP
# scenarios, the headers are also embedded in `input.requestHeaders`
# because OPA only sees the POST body (the HTTP HeaderManager entries
# still ride along but are irrelevant to OPA's evaluation).

def _groovy_request_headers_map(spec: dict) -> str:
    """Render the (name, value) header tuples as a Groovy map literal,
    suitable for embedding in `input.requestHeaders`. Returns `[:]` when
    the scenario has no header-PIP headers."""
    pairs = header_extras_for_spec(spec)
    if not pairs:
        return "[:]"
    entries = ", ".join(f'"{name}": "{value}"' for name, value in pairs)
    return "[" + entries + "]"


def _groovy_ols_single(spec: dict, mod, scenario_token_var: str) -> str:
    """Single-resource OLS body with ignoreRls:true. The role list comes
    from the user's token, not the body."""
    rt = mod.rt_name(spec["scenario"], 1)
    op = mod.op_name(spec["scenario"], 1)
    req_headers_map = _groovy_request_headers_map(spec)
    return f"""
import groovy.json.JsonBuilder
def mode = props.get("mode") ?: "canonical"
def token = props.get("{scenario_token_var}") ?: ""
vars.put("auth_token", token)
def rt = "{rt}"
def op = "{op}"
if (mode == "canonical") {{
  vars.put("req_path", "/access/v1/authorize")
  vars.put("req_body",
    '{{"input":{{"resources":[{{"resourceType":"' + rt + '","operation":"' + op + '","resource":{{}}}}],"subject":"Bearer ' + token + '","ignoreRls":true}}}}')
  vars.put("body_raw", "true")
}} else if (mode == "opa-direct") {{
  vars.put("req_path", "/v1/data/authorize")
  vars.put("req_body", new JsonBuilder([input: [
    authorizationToken: "Bearer " + token,
    authorizationType: "",
    requestHeaders: {req_headers_map},
    decisionLogPipTrace: true,
    resources: [[resourceType: rt, operation: op, resource: [:]]],
    subject: "Bearer " + token,
    ignoreRls: true
  ]]).toString())
  vars.put("body_raw", "true")
}} else {{
  vars.put("req_path", "/access/v1/check/resource")
  vars.put("req_body",
    '{{"type":"' + rt + '","operation":"' + op + '","resource":{{}}}}')
  vars.put("body_raw", "true")
}}
"""


def _groovy_ols_bulk(spec: dict, mod, scenario_token_var: str) -> str:
    """Bulk-OLS body: bulk_rt_count × bulk_op_count resources, every
    cell uses an empty resource:{} (the profiler does the same)."""
    n_rt = int(spec["bulk_rt_count"])
    n_op = int(spec["bulk_op_count"])
    tag = mod.scenario_tag(spec["scenario"])
    req_headers_map = _groovy_request_headers_map(spec)
    return f"""
import groovy.json.JsonBuilder
def mode = props.get("mode") ?: "canonical"
def token = props.get("{scenario_token_var}") ?: ""
vars.put("auth_token", token)
def resources = []
def bulkItems = []
def idx = 0
(1..{n_rt}).each {{ rti ->
  def rt = String.format("PS_{tag}_RT_%02d", rti)
  (1..{n_op}).each {{ opi ->
    def op = String.format("PS_{tag}_OP_%02d", opi)
    resources &lt;&lt; [resourceType: rt, operation: op, resource: [:]]
    idx++
    bulkItems &lt;&lt; [type: rt, operation: op, resource: [:], id: "b-" + idx]
  }}
}}
if (mode == "canonical") {{
  vars.put("req_path", "/access/v1/authorize")
  vars.put("req_body", new JsonBuilder([input: [resources: resources, subject: "Bearer " + token, ignoreRls: true]]).toString())
  vars.put("body_raw", "true")
}} else if (mode == "opa-direct") {{
  vars.put("req_path", "/v1/data/authorize")
  vars.put("req_body", new JsonBuilder([input: [
    authorizationToken: "Bearer " + token,
    authorizationType: "",
    requestHeaders: {req_headers_map},
    decisionLogPipTrace: true,
    resources: resources,
    subject: "Bearer " + token,
    ignoreRls: true
  ]]).toString())
  vars.put("body_raw", "true")
}} else {{
  vars.put("req_path", "/access/v1/check/resource/bulk")
  vars.put("req_body", new JsonBuilder(bulkItems).toString())
  vars.put("body_raw", "true")
}}
"""


def _groovy_rls_condition(spec: dict, mod, scenario_token_var: str) -> str:
    """RLS-condition body — single resource with ignoreRls:false. Legacy
    uses /access/v1/check/resource (per the inventory table)."""
    rt = mod.rt_name(spec["scenario"], 1)
    op = mod.op_name(spec["scenario"], 1)
    req_headers_map = _groovy_request_headers_map(spec)
    return f"""
import groovy.json.JsonBuilder
def mode = props.get("mode") ?: "canonical"
def token = props.get("{scenario_token_var}") ?: ""
vars.put("auth_token", token)
def rt = "{rt}"
def op = "{op}"
if (mode == "canonical") {{
  vars.put("req_path", "/access/v1/authorize")
  vars.put("req_body",
    '{{"input":{{"resources":[{{"resourceType":"' + rt + '","operation":"' + op + '","resource":{{}}}}],"subject":"Bearer ' + token + '","ignoreRls":false}}}}')
  vars.put("body_raw", "true")
}} else if (mode == "opa-direct") {{
  vars.put("req_path", "/v1/data/authorize")
  vars.put("req_body", new JsonBuilder([input: [
    authorizationToken: "Bearer " + token,
    authorizationType: "",
    requestHeaders: {req_headers_map},
    decisionLogPipTrace: true,
    resources: [[resourceType: rt, operation: op, resource: [:]]],
    subject: "Bearer " + token,
    ignoreRls: false
  ]]).toString())
  vars.put("body_raw", "true")
}} else {{
  vars.put("req_path", "/access/v1/check/resource")
  vars.put("req_body",
    '{{"type":"' + rt + '","operation":"' + op + '","resource":{{}}}}')
  vars.put("body_raw", "true")
}}
"""


def _groovy_rls_predicate(spec: dict, mod, scenario_token_var: str) -> str:
    """RLS-predicate body — single resource with ignoreRls:false.
    Legacy is /access/v1/check/filter?resourceType&operation."""
    rt = mod.rt_name(spec["scenario"], 1)
    op = mod.op_name(spec["scenario"], 1)
    req_headers_map = _groovy_request_headers_map(spec)
    return f"""
import groovy.json.JsonBuilder
def mode = props.get("mode") ?: "canonical"
def token = props.get("{scenario_token_var}") ?: ""
vars.put("auth_token", token)
def rt = "{rt}"
def op = "{op}"
if (mode == "canonical") {{
  vars.put("req_path", "/access/v1/authorize")
  vars.put("req_body",
    '{{"input":{{"resources":[{{"resourceType":"' + rt + '","operation":"' + op + '","resource":{{}}}}],"subject":"Bearer ' + token + '","ignoreRls":false}}}}')
  vars.put("body_raw", "true")
}} else if (mode == "opa-direct") {{
  vars.put("req_path", "/v1/data/authorize")
  vars.put("req_body", new JsonBuilder([input: [
    authorizationToken: "Bearer " + token,
    authorizationType: "",
    requestHeaders: {req_headers_map},
    decisionLogPipTrace: true,
    resources: [[resourceType: rt, operation: op, resource: [:]]],
    subject: "Bearer " + token,
    ignoreRls: false
  ]]).toString())
  vars.put("body_raw", "true")
}} else {{
  vars.put("req_path", "/access/v1/check/filter?resourceType=" + rt + "&amp;operation=" + op)
  vars.put("req_body", "")
  vars.put("body_raw", "false")
}}
"""


def _groovy_wildcard_single(spec, mod, scenario_token_var: str) -> str:
    """wildcard-all-single: identical body shape to ols-single but
    ignoreRls:false because the role grant is via a `true` predicate."""
    rt = mod.rt_name(spec["scenario"], 1)
    op = mod.op_name(spec["scenario"], 1)
    req_headers_map = _groovy_request_headers_map(spec)
    return f"""
import groovy.json.JsonBuilder
def mode = props.get("mode") ?: "canonical"
def token = props.get("{scenario_token_var}") ?: ""
vars.put("auth_token", token)
def rt = "{rt}"
def op = "{op}"
if (mode == "canonical") {{
  vars.put("req_path", "/access/v1/authorize")
  vars.put("req_body",
    '{{"input":{{"resources":[{{"resourceType":"' + rt + '","operation":"' + op + '","resource":{{}}}}],"subject":"Bearer ' + token + '","ignoreRls":false}}}}')
  vars.put("body_raw", "true")
}} else if (mode == "opa-direct") {{
  vars.put("req_path", "/v1/data/authorize")
  vars.put("req_body", new JsonBuilder([input: [
    authorizationToken: "Bearer " + token,
    authorizationType: "",
    requestHeaders: {req_headers_map},
    decisionLogPipTrace: true,
    resources: [[resourceType: rt, operation: op, resource: [:]]],
    subject: "Bearer " + token,
    ignoreRls: false
  ]]).toString())
  vars.put("body_raw", "true")
}} else {{
  vars.put("req_path", "/access/v1/check/resource")
  vars.put("req_body",
    '{{"type":"' + rt + '","operation":"' + op + '","resource":{{}}}}')
  vars.put("body_raw", "true")
}}
"""


def _groovy_wildcard_bulk(spec, mod, scenario_token_var: str) -> str:
    """wildcard-mixed-bulk: same payload shape as ols-bulk, with
    ignoreRls:false (every cell carries the `true` RLS predicate)."""
    n_rt = int(spec["bulk_rt_count"])
    n_op = int(spec["bulk_op_count"])
    tag = mod.scenario_tag(spec["scenario"])
    req_headers_map = _groovy_request_headers_map(spec)
    return f"""
import groovy.json.JsonBuilder
def mode = props.get("mode") ?: "canonical"
def token = props.get("{scenario_token_var}") ?: ""
vars.put("auth_token", token)
def resources = []
def bulkItems = []
def idx = 0
(1..{n_rt}).each {{ rti ->
  def rt = String.format("PS_{tag}_RT_%02d", rti)
  (1..{n_op}).each {{ opi ->
    def op = String.format("PS_{tag}_OP_%02d", opi)
    resources &lt;&lt; [resourceType: rt, operation: op, resource: [:]]
    idx++
    bulkItems &lt;&lt; [type: rt, operation: op, resource: [:], id: "b-" + idx]
  }}
}}
if (mode == "canonical") {{
  vars.put("req_path", "/access/v1/authorize")
  vars.put("req_body", new JsonBuilder([input: [resources: resources, subject: "Bearer " + token, ignoreRls: false]]).toString())
  vars.put("body_raw", "true")
}} else if (mode == "opa-direct") {{
  vars.put("req_path", "/v1/data/authorize")
  vars.put("req_body", new JsonBuilder([input: [
    authorizationToken: "Bearer " + token,
    authorizationType: "",
    requestHeaders: {req_headers_map},
    decisionLogPipTrace: true,
    resources: resources,
    subject: "Bearer " + token,
    ignoreRls: false
  ]]).toString())
  vars.put("body_raw", "true")
}} else {{
  vars.put("req_path", "/access/v1/check/resource/bulk")
  vars.put("req_body", new JsonBuilder(bulkItems).toString())
  vars.put("body_raw", "true")
}}
"""


GROOVY_FOR_KIND = {
    "ols_single": _groovy_ols_single,
    "ols_bulk": _groovy_ols_bulk,
    "rls_condition": _groovy_rls_condition,
    "rls_predicate": _groovy_rls_predicate,
    "rls_predicate_summary_compound": _groovy_rls_predicate,
    "wildcard_single": _groovy_wildcard_single,
    "wildcard_bulk": _groovy_wildcard_bulk,
}


# ── per-scenario optional header injection ────────────────────────────────

def header_extras_for_spec(spec: dict) -> list[tuple[str, str]]:
    """Return the (name, value) header tuples that JMeter must add for
    header-PIP scenarios. The value strings are deterministic but
    arbitrary — the predicate fires the PIP regardless of the actual
    value (the decision outcome is irrelevant; we measure cost)."""
    headers: list[tuple[str, str]] = []
    kind = spec["kind"]
    if kind not in ("rls_condition", "rls_predicate",
                    "rls_predicate_summary_compound"):
        return headers
    predicates = spec.get("conditions", spec.get("predicates", []))
    seen = set()
    for entry in predicates:
        if len(entry) != 3:
            continue
        _field, claim, source = entry
        if source != "header":
            continue
        if claim == "regionFromHeader" and "x-svt-region" not in seen:
            headers.append(("x-svt-region", "region-01"))
            seen.add("x-svt-region")
        elif claim == "countryFromHeader" and "x-svt-country" not in seen:
            headers.append(("x-svt-country", "country-01"))
            seen.add("x-svt-country")
        elif claim == "divisionFromHeader" and "x-svt-division" not in seen:
            headers.append(("x-svt-division", "division-01"))
            seen.add("x-svt-division")
    return headers


# ── JMX template ──────────────────────────────────────────────────────────

JMX_HEADER = """<?xml version="1.0" encoding="UTF-8"?>
<jmeterTestPlan version="1.2" properties="5.0" jmeter="5.6.3">
  <hashTree>
    <TestPlan guiclass="TestPlanGui" testclass="TestPlan" testname="Per-Scenario Authz SVT — {scenario}" enabled="true">
      <stringProp name="TestPlan.comments">Per-scenario load-test plan for the authz-agent decision-time sweep.
Single thread group; the `${{MODE}}` switch maps:
  canonical  → POST /access/v1/authorize on Envoy (${{AUTHZ_HOST}}:${{AUTHZ_PORT}})
  legacy     → POST {legacy_endpoint} on Envoy
  opa-direct → POST /v1/data/authorize on OPA (point AUTHZ_HOST/AUTHZ_PORT at opa:8181)
Token property: token_svt_bench_{scenario_underscored} (issued by Keycloak for svt-bench-{scenario}).</stringProp>
      <boolProp name="TestPlan.functional_mode">false</boolProp>
      <boolProp name="TestPlan.serialize_threadgroups">false</boolProp>
      <elementProp name="TestPlan.user_defined_variables" elementType="Arguments">
        <collectionProp name="Arguments.arguments">
          <elementProp name="AUTHZ_HOST" elementType="Argument">
            <stringProp name="Argument.name">AUTHZ_HOST</stringProp>
            <stringProp name="Argument.value">${{__P(authz_host,envoy)}}</stringProp>
          </elementProp>
          <elementProp name="AUTHZ_PORT" elementType="Argument">
            <stringProp name="Argument.name">AUTHZ_PORT</stringProp>
            <stringProp name="Argument.value">${{__P(authz_port,8080)}}</stringProp>
          </elementProp>
          <elementProp name="MODE" elementType="Argument">
            <stringProp name="Argument.name">MODE</stringProp>
            <stringProp name="Argument.value">${{__P(mode,canonical)}}</stringProp>
          </elementProp>
          <elementProp name="THREADS" elementType="Argument">
            <stringProp name="Argument.name">THREADS</stringProp>
            <stringProp name="Argument.value">${{__P(threads,10)}}</stringProp>
          </elementProp>
          <elementProp name="RAMP_SECONDS" elementType="Argument">
            <stringProp name="Argument.name">RAMP_SECONDS</stringProp>
            <stringProp name="Argument.value">${{__P(ramp_seconds,5)}}</stringProp>
          </elementProp>
          <elementProp name="DURATION_SECONDS" elementType="Argument">
            <stringProp name="Argument.name">DURATION_SECONDS</stringProp>
            <stringProp name="Argument.value">${{__P(duration_seconds,60)}}</stringProp>
          </elementProp>
          <elementProp name="TARGET_RPS" elementType="Argument">
            <stringProp name="Argument.name">TARGET_RPS</stringProp>
            <stringProp name="Argument.value">${{__P(target_rps,100)}}</stringProp>
          </elementProp>
        </collectionProp>
      </elementProp>
    </TestPlan>
    <hashTree>
"""

JMX_THREAD_GROUP = """
      <ThreadGroup guiclass="ThreadGroupGui" testclass="ThreadGroup" testname="PS — {scenario}" enabled="true">
        <stringProp name="ThreadGroup.on_sample_error">continue</stringProp>
        <elementProp name="ThreadGroup.main_controller" elementType="LoopController">
          <boolProp name="LoopController.continue_forever">false</boolProp>
          <intProp name="LoopController.loops">-1</intProp>
        </elementProp>
        <stringProp name="ThreadGroup.num_threads">${{THREADS}}</stringProp>
        <stringProp name="ThreadGroup.ramp_time">${{RAMP_SECONDS}}</stringProp>
        <boolProp name="ThreadGroup.scheduler">true</boolProp>
        <stringProp name="ThreadGroup.duration">${{DURATION_SECONDS}}</stringProp>
        <stringProp name="ThreadGroup.delay">0</stringProp>
      </ThreadGroup>
      <hashTree>
        <ConstantThroughputTimer guiclass="TestBeanGUI" testclass="ConstantThroughputTimer" testname="Rate Limiter (100%)" enabled="true">
          <stringProp name="throughput">${{__jexl3(${{TARGET_RPS}} * 60)}}</stringProp>
          <intProp name="calcMode">2</intProp>
        </ConstantThroughputTimer>
        <hashTree/>
        <JSR223PreProcessor guiclass="TestBeanGUI" testclass="JSR223PreProcessor" testname="Build request" enabled="true">
          <stringProp name="scriptLanguage">groovy</stringProp>
          <stringProp name="script">{groovy_body}</stringProp>
        </JSR223PreProcessor>
        <hashTree/>
        <HeaderManager guiclass="HeaderPanel" testclass="HeaderManager" testname="Headers" enabled="true">
          <collectionProp name="HeaderManager.headers">
            <elementProp name="" elementType="Header">
              <stringProp name="Header.name">Content-Type</stringProp>
              <stringProp name="Header.value">application/json</stringProp>
            </elementProp>
            <elementProp name="" elementType="Header">
              <stringProp name="Header.name">Authorization</stringProp>
              <stringProp name="Header.value">Bearer ${{auth_token}}</stringProp>
            </elementProp>{header_extra_xml}
          </collectionProp>
        </HeaderManager>
        <hashTree/>
        <HTTPSamplerProxy guiclass="HttpTestSampleGui" testclass="HTTPSamplerProxy" testname="POST [{scenario}]" enabled="true">
          <boolProp name="HTTPSampler.postBodyRaw">${{body_raw}}</boolProp>
          <elementProp name="HTTPsampler.Arguments" elementType="Arguments">
            <collectionProp name="Arguments.arguments">
              <elementProp name="" elementType="HTTPArgument">
                <boolProp name="HTTPArgument.always_encode">false</boolProp>
                <stringProp name="Argument.value">${{req_body}}</stringProp>
                <stringProp name="Argument.metadata">=</stringProp>
              </elementProp>
            </collectionProp>
          </elementProp>
          <stringProp name="HTTPSampler.domain">${{AUTHZ_HOST}}</stringProp>
          <stringProp name="HTTPSampler.port">${{AUTHZ_PORT}}</stringProp>
          <stringProp name="HTTPSampler.protocol">http</stringProp>
          <stringProp name="HTTPSampler.path">${{req_path}}</stringProp>
          <stringProp name="HTTPSampler.method">POST</stringProp>
          <boolProp name="HTTPSampler.use_keepalive">true</boolProp>
        </HTTPSamplerProxy>
        <hashTree>
          <JSR223PostProcessor guiclass="TestBeanGUI" testclass="JSR223PostProcessor" testname="Label" enabled="true">
            <stringProp name="scriptLanguage">groovy</stringProp>
            <stringProp name="script">prev.setSampleLabel("{scenario} [" + (props.get("mode") ?: "canonical") + "]")</stringProp>
          </JSR223PostProcessor>
          <hashTree/>
        </hashTree>
      </hashTree>
"""

JMX_FOOTER = """
      <ResultCollector guiclass="SummaryReport" testclass="ResultCollector" testname="Summary Report" enabled="true">
        <boolProp name="ResultCollector.error_logging">false</boolProp>
        <objProp>
          <name>saveConfig</name>
          <value class="SampleSaveConfiguration">
            <time>true</time>
            <latency>true</latency>
            <timestamp>true</timestamp>
            <success>true</success>
            <label>true</label>
            <code>true</code>
            <message>true</message>
            <threadName>true</threadName>
            <dataType>true</dataType>
            <encoding>false</encoding>
            <assertions>true</assertions>
            <subresults>true</subresults>
            <responseData>false</responseData>
            <samplerData>false</samplerData>
            <xml>false</xml>
            <fieldNames>true</fieldNames>
            <responseHeaders>false</responseHeaders>
            <requestHeaders>false</requestHeaders>
            <responseDataOnError>false</responseDataOnError>
            <saveAssertionResultsFailureMessage>true</saveAssertionResultsFailureMessage>
            <bytes>true</bytes>
            <sentBytes>true</sentBytes>
            <url>true</url>
            <connectTime>true</connectTime>
          </value>
        </objProp>
        <stringProp name="filename"></stringProp>
      </ResultCollector>
      <hashTree/>

    </hashTree>
  </hashTree>
</jmeterTestPlan>
"""


def render_jmx(spec: dict, mod) -> str:
    scenario = spec["scenario"]
    underscored = scenario.replace("-", "_")
    groovy = GROOVY_FOR_KIND[spec["kind"]](spec, mod, f"token_svt_bench_{underscored}")
    header_extras = header_extras_for_spec(spec)
    header_extra_xml = "".join(
        f"""
            <elementProp name="" elementType="Header">
              <stringProp name="Header.name">{name}</stringProp>
              <stringProp name="Header.value">{value}</stringProp>
            </elementProp>"""
        for name, value in header_extras
    )
    head = JMX_HEADER.format(
        scenario=scenario,
        legacy_endpoint=spec["legacy_endpoint"],
        scenario_underscored=underscored,
    )
    body = JMX_THREAD_GROUP.format(
        scenario=scenario,
        groovy_body=groovy,
        header_extra_xml=header_extra_xml,
    )
    return head + body + JMX_FOOTER


# ── per-RPS directory artefacts ───────────────────────────────────────────

CONFIG_ENV_TEMPLATE = """# Test configuration: per-scenario {scenario} {rps} RPS
# Drives a single bench-report scenario at the per-directory target RPS.
# See docs/handovers/20260518-per-scenario-decision-time-task.md.
TARGET_RPS="${{TARGET_RPS:-{rps}}}"
THREADS="${{THREADS:-{threads}}}"
RAMP_SECONDS="${{RAMP_SECONDS:-{ramp}}}"
DURATION_SECONDS="${{DURATION_SECONDS:-{duration}}}"
MODE="${{MODE:-canonical}}"
"""

RUN_TEMPLATE = """#!/usr/bin/env bash
# Per-scenario <rps>RPS load-test runner.
#
# Standalone entry point — restarts OPA into a cold-cache state, acquires
# Keycloak tokens for every SVT user (including 28 svt-bench-* users
# added by the per-scenario decision-time task), then runs the
# scenario-specific JMX at the per-directory TARGET_RPS for
# DURATION_SECONDS. Driven by tests/svt/scripts/per-scenario-decision-time
# during a sweep; can also be invoked alone for ad-hoc runs.
#
# Transport modes:
#   canonical / legacy → Envoy boundary, host-networked jmeter-host
#                         (svt_run_jmeter_mixed_flow → localhost:${SVT_AUTHZ_PORT}).
#   opa-direct         → OPA boundary, bridged jmeter (svt_run_jmeter_per_scenario_opa_direct
#                         → opa:8181, /v1/data/authorize). OPA's port is
#                         NOT exposed to the host, so the bridged service is required.
set -euo pipefail

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCENARIO_DIR="$(cd "${TEST_DIR}/.." && pwd)"
SVT_DIR="$(cd "${SCENARIO_DIR}/../../.." && pwd)"
# shellcheck source=../../../../common/scripts/lib/svt-lib.sh
source "${SVT_DIR}/common/scripts/lib/svt-lib.sh"
# shellcheck source=config.env
source "${TEST_DIR}/config.env"

JMX_PATH="${SCENARIO_DIR}/test.jmx"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
ARTIFACTS_DIR="${ARTIFACTS_DIR:-${TEST_DIR}/artifacts/${TIMESTAMP}}"
mkdir -p "${ARTIFACTS_DIR}"

if [[ "${MODE}" == "opa-direct" ]]; then
  svt_preflight_backend
else
  svt_preflight_public
fi
svt_acquire_all_tokens

TOKENS_FILE="${ARTIFACTS_DIR}/tokens.properties"
svt_write_tokens_file "${TOKENS_FILE}"

svt_restart_opa
if [[ "${MODE}" == "opa-direct" ]]; then
  svt_run_jmeter_per_scenario_opa_direct "${MODE}" "${ARTIFACTS_DIR}" "${JMX_PATH}" \\
    "${TARGET_RPS}" "${THREADS}" "${RAMP_SECONDS}" "${DURATION_SECONDS}" \\
    "${TOKENS_FILE}"
else
  svt_run_jmeter_mixed_flow "${MODE}" "${ARTIFACTS_DIR}" "${JMX_PATH}" \\
    "${TARGET_RPS}" "${THREADS}" "${RAMP_SECONDS}" "${DURATION_SECONDS}" \\
    "${TOKENS_FILE}"
fi

svt_log "per-scenario ${MODE} ${TARGET_RPS}RPS complete — artifacts: ${ARTIFACTS_DIR}"
"""

SCENARIO_MD_TEMPLATE = """# Scenario: Per-Scenario {scenario} — {rps} RPS

## Type
per-scenario

## Target RPS
{rps}

## Parameters
| Parameter | Value |
|-----------|-------|
| Threads | {threads} |
| Ramp | {ramp}s |
| Duration | {duration}s |
| Target RPS | {rps} |
| Mode | canonical, legacy, or opa-direct (via ${{MODE}} property) |

## Description
Single-thread-group plan exercising the `{scenario}` bench-report scenario.
The `${{MODE}}` switch selects:

- `canonical`  → Envoy → OPA → decision-log-collector: `POST /access/v1/authorize`
- `legacy`     → Envoy → OPA → decision-log-collector: `POST {legacy_endpoint}`
- `opa-direct` → OPA → decision-log-collector (Envoy bypassed):
  `POST /v1/data/authorize` on `opa:8181`

The shared per-scenario JMX lives at
`tests/svt/load-tests/per-scenario/{scenario}/test.jmx`; per-RPS directories
differ only in `config.env`. The driver script
`tests/svt/scripts/per-scenario-decision-time --mode <canonical|legacy|opa-direct> \\
  --scenarios {scenario}` invokes the per-RPS `run` in ascending order
and assembles a per-scenario block in the consolidated report.

## See also
- [docs/handovers/20260518-per-scenario-decision-time-task.md](../../../../docs/handovers/20260518-per-scenario-decision-time-task.md)
- [docs/handovers/20260521-canonical-per-scenario-reports-opa-direct-task.md](../../../../docs/handovers/20260521-canonical-per-scenario-reports-opa-direct-task.md)
- [docs/reports/per-scenario-decision-time-canonical-latest.md](../../../../docs/reports/per-scenario-decision-time-canonical-latest.md)
- [docs/reports/per-scenario-decision-time-legacy-latest.md](../../../../docs/reports/per-scenario-decision-time-legacy-latest.md)
- [docs/reports/per-scenario-decision-time-opa-direct-latest.md](../../../../docs/reports/per-scenario-decision-time-opa-direct-latest.md)
"""


def write_scenario_artifacts(spec: dict, mod) -> None:
    scenario = spec["scenario"]
    scenario_dir = os.path.join(LOAD_TESTS_ROOT, scenario)
    _ensure_dir(scenario_dir)
    # Per-scenario artifacts root (preserves timestamped sweep output).
    _ensure_dir(os.path.join(scenario_dir, "artifacts"))
    _write_text(os.path.join(scenario_dir, "artifacts", ".gitkeep"), "")
    # JMX.
    _write_text(os.path.join(scenario_dir, "test.jmx"), render_jmx(spec, mod))
    # Per-RPS sub-directories.
    for rps in RPS_LEVELS:
        rps_dir = os.path.join(scenario_dir, f"{rps}rps")
        _ensure_dir(rps_dir)
        _ensure_dir(os.path.join(rps_dir, "artifacts"))
        _write_text(os.path.join(rps_dir, "artifacts", ".gitkeep"), "")
        _write_text(
            os.path.join(rps_dir, "config.env"),
            CONFIG_ENV_TEMPLATE.format(
                scenario=scenario,
                rps=rps,
                threads=THREADS_FOR_RPS[rps],
                ramp=RAMP_SECONDS,
                duration=DURATION_SECONDS,
            ),
        )
        _write_text(
            os.path.join(rps_dir, "run"),
            RUN_TEMPLATE,
            make_executable=True,
        )
        _write_text(
            os.path.join(rps_dir, "scenario.md"),
            SCENARIO_MD_TEMPLATE.format(
                scenario=scenario,
                rps=rps,
                threads=THREADS_FOR_RPS[rps],
                ramp=RAMP_SECONDS,
                duration=DURATION_SECONDS,
                legacy_endpoint=spec["legacy_endpoint"],
            ),
        )


def main() -> int:
    mod = _load_inventory()
    _ensure_dir(LOAD_TESTS_ROOT)
    # Top-level per-scenario sweep artifacts root (timestamped sweep
    # output from the orchestrator lands here).
    _ensure_dir(os.path.join(LOAD_TESTS_ROOT, "artifacts"))
    _write_text(os.path.join(LOAD_TESTS_ROOT, "artifacts", ".gitkeep"), "")
    for spec in mod.SCENARIOS:
        write_scenario_artifacts(spec, mod)
    n_scenarios = len(mod.SCENARIOS)
    n_rps = len(RPS_LEVELS)
    print(
        f"wrote {n_scenarios} JMX files + {n_scenarios * n_rps} per-RPS "
        f"directories under {LOAD_TESTS_ROOT}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
