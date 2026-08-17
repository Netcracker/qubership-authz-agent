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

package system.authz

import rego.v1

# OPA data API authorization policy (--authorization=basic + --authentication=token).
#
# DESIGN DECISION (authz-agent-ADR-0077, amended 2026-07-31):
# Both --authorization=basic and --authentication=token are required together.
#
# --authorization=basic  → OPA evaluates this package on every HTTP request.
# --authentication=token → When a Bearer token is present in the Authorization
#                          header, OPA strips the "Bearer " prefix and stores the
#                          token string in input.identity. When no Authorization
#                          header is sent, input.identity is undefined.
#
# Write paths (PUT/PATCH /v1/data/**) require input.identity to equal
# data.opa_auth_secret. The secret is loaded from the JSON file written to
# ${OPA_DATA_DIR}/opa-auth-secret.json by the start script before OPA starts,
# using the value from the Helm-generated Secret (see authz-agent-ADR-0077
# and charts/authz-agent/templates/secret.yaml).
#
# NOTE: Rego has no constant-time string comparison, so the identity check is
# a plain equality test. This is acceptable because an attacker would need
# in-cluster network access to OPA's unencrypted loopback port to mount a
# timing attack — the token is an internal credential, not a user-facing secret.
# See ADR-0077 §Consequences.
#
# Callers audited (2026-08-04):
#   POST  /v1/data/authorize              — Envoy, direct callers (ADR-0062), tests
#   PUT   /v1/data/policies               — pap-client (policy push)
#   PUT   /v1/data/pips                   — pap-client (PIP configuration)
#   PUT   /v1/data/m2m                    — pap-client (token_watcher.go)
#   PATCH /v1/data/authn                  — providers_reload.go (JSON Patch)
#   PUT   /v1/data/authn                  — providers_reload.go (fallback)
#   GET   /health                         — OPA liveness/readiness probes
#
# Explicitly blocked without a valid OPA auth token:
#   PUT/PATCH /v1/data/**  (any path)    — write paths require identity
#   GET   /v1/data/m2m                   — exposes the M2M bearer token to all pods
#   GET   /v1/data/*  (any other path)   — data read paths blocked from outside
#
# Blocked for everyone, token or not:
#   POST  /v1/data/authorize?explain=…   — the trace leaks the M2M token and the
#     (also instrument / metrics / provenance)  caller's decoded token

# Default: deny everything.
default allow := false

# ── POST /v1/data/authorize ──────────────────────────────────────────────────
# Canonical authorization endpoint. Reached by Envoy (via prefix_rewrite),
# direct OPA-direct callers (ADR-0062), integration test suites, and SVT.
# External callers (including public gateways) have no OPA bearer token and
# must never be required to present one — keeping this endpoint unconditionally
# open is a hard requirement of ADR-0062 and mesh-routes.yaml.
#
# ...but "open" applies to the DECISION, not to OPA's introspection facilities.
# The Data API honours query parameters on this very POST, and `?explain=full`
# returns the evaluation trace, whose `locals` carry resolved variable values —
# including data.m2m.bearerToken as bound by pip.rego, the decoded caller token,
# and the policy data the decision touched. mesh-routes.yaml publishes
# /access/v1/authorize on the PUBLIC gateway with a prefix rewrite, and Envoy's
# prefix_rewrite preserves the query string, so without the guard below an
# anonymous caller could read the agent's M2M credential off the public
# internet. The rewrite pins the PATH; it does nothing about parameters.
#
# `explain` is therefore denied for everyone on this route — there is no
# legitimate caller of the canonical endpoint that needs a trace, and an
# operator who does can query OPA from inside the Pod with the auth token.
allow if {
	input.method == "POST"
	input.path == ["v1", "data", "authorize"]
	not introspection_requested
}

# introspection_requested is true when the request asks OPA to reveal how the
# decision was reached rather than only what it was. `explain` is the leak that
# matters (it carries values); `instrument` and `metrics` only add timings, and
# `provenance` build info — all three are refused alongside it because the
# canonical endpoint has no use for any of them, and a narrow allow-list ages
# better than an enumeration of what happens to be dangerous today.
introspection_requested if input.params.explain
introspection_requested if input.params.instrument
introspection_requested if input.params.metrics
introspection_requested if input.params.provenance

# ── PUT /v1/data/* — pap-client writes ────────────────────────────────────
# pap-client PUTs normalized policies, PIPs, the M2M bearer token, and authn
# data. Identity required: input.identity must equal the shared OPA auth secret.
# With --authentication=token, input.identity holds the bare token string from
# the Authorization: Bearer header (prefix stripped by OPA). When no
# Authorization header is present, input.identity is undefined → deny.
#
# The input.identity != "" guard closes a residual corner case: if the OPA
# secret were ever rendered as an empty string (e.g. a misconfigured Helm
# value) and the caller sent an empty Bearer token, a plain equality test would
# admit the request. An empty identity can never be a legitimate credential.
allow if {
	input.method == "PUT"
	count(input.path) >= 2
	input.path[0] == "v1"
	input.path[1] == "data"
	input.identity != ""
	input.identity == data.opa_auth_secret
}

# ── PATCH /v1/data/authn — providers_reload.go ──────────────────────────────
# providers_reload.go uses JSON Patch to update /v1/data/authn atomically.
# Identity required: same shared secret as PUT paths above.
allow if {
	input.method == "PATCH"
	count(input.path) >= 3
	input.path[0] == "v1"
	input.path[1] == "data"
	input.path[2] == "authn"
	input.identity != ""
	input.identity == data.opa_auth_secret
}

# ── GET /health — OPA readiness probe ───────────────────────────────────────
# pap-client's handleHealth calls checkOPAReady, which GETs /health.
# In practice /health bypasses both --authentication and --authorization in
# OPA, but this rule is kept for explicitness and defensive correctness.
allow if {
	input.method == "GET"
	input.path == ["health"]
}
