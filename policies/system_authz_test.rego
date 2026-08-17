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

package system.authz_test

import rego.v1

# Unit tests for the OPA Data API authorization policy (authz-agent-ADR-0077).
#
# Before this file the policy had no unit coverage at all: the only checks were
# three runtime assertions in tests/integration/testify/opa_lockdown_test.go
# (GET /v1/data/pips → 401, PUT without token → 401, PUT with token → 204).
# That left the interesting cases untested — a WRONG token, the introspection
# parameters, and every method/path combination the audit comment claims is
# blocked. system.authz is a pure function of `input`, so it is cheap to pin.

secret := "s3cr3t-opa-token"

authz_data := {"opa_auth_secret": secret}

allowed(req) if {
	data.system.authz.allow with input as req with data.opa_auth_secret as secret
}

# ── The canonical decision endpoint stays open ───────────────────────────────

test_authorize_post_allowed_without_identity if {
	allowed({"method": "POST", "path": ["v1", "data", "authorize"]})
}

test_authorize_post_allowed_with_pretty_param if {
	allowed({
		"method": "POST",
		"path": ["v1", "data", "authorize"],
		"params": {"pretty": ["true"]},
	})
}

# ── ...but introspection on it is refused for everyone ──────────────────────
# The leak: ?explain=full returns the evaluation trace, whose locals carry
# data.m2m.bearerToken and the decoded caller token. The canonical route is
# published on the PUBLIC gateway and Envoy's prefix_rewrite keeps the query
# string, so this is an unauthenticated credential read if left open.

test_authorize_explain_full_denied if {
	not allowed({
		"method": "POST",
		"path": ["v1", "data", "authorize"],
		"params": {"explain": ["full"]},
	})
}

test_authorize_explain_notes_denied if {
	not allowed({
		"method": "POST",
		"path": ["v1", "data", "authorize"],
		"params": {"explain": ["notes"]},
	})
}

test_authorize_explain_denied_even_with_valid_token if {
	not allowed({
		"method": "POST",
		"path": ["v1", "data", "authorize"],
		"params": {"explain": ["full"]},
		"identity": secret,
	})
}

test_authorize_instrument_denied if {
	not allowed({
		"method": "POST",
		"path": ["v1", "data", "authorize"],
		"params": {"instrument": ["true"]},
	})
}

test_authorize_metrics_denied if {
	not allowed({
		"method": "POST",
		"path": ["v1", "data", "authorize"],
		"params": {"metrics": ["true"]},
	})
}

test_authorize_provenance_denied if {
	not allowed({
		"method": "POST",
		"path": ["v1", "data", "authorize"],
		"params": {"provenance": ["true"]},
	})
}

# ── Writes require the shared secret ─────────────────────────────────────────

test_put_policies_allowed_with_correct_identity if {
	allowed({"method": "PUT", "path": ["v1", "data", "policies"], "identity": secret})
}

test_put_m2m_allowed_with_correct_identity if {
	allowed({"method": "PUT", "path": ["v1", "data", "m2m"], "identity": secret})
}

test_put_denied_without_identity if {
	not allowed({"method": "PUT", "path": ["v1", "data", "pips"]})
}

# The integration suite only ever sends the RIGHT token or none, so nothing
# there distinguishes "compares against the secret" from "accepts any token".
test_put_denied_with_wrong_identity if {
	not allowed({"method": "PUT", "path": ["v1", "data", "pips"], "identity": "not-the-secret"})
}

test_put_denied_with_empty_identity if {
	not allowed({"method": "PUT", "path": ["v1", "data", "pips"], "identity": ""})
}

test_patch_authn_allowed_with_correct_identity if {
	allowed({"method": "PATCH", "path": ["v1", "data", "authn"], "identity": secret})
}

test_patch_denied_with_wrong_identity if {
	not allowed({"method": "PATCH", "path": ["v1", "data", "authn"], "identity": "nope"})
}

test_patch_denied_with_empty_identity if {
	not allowed({"method": "PATCH", "path": ["v1", "data", "authn"], "identity": ""})
}

# ── Empty-secret corner case ─────────────────────────────────────────────────
# If opa_auth_secret were ever rendered as "" (misconfigured Helm value) and a
# caller sent an empty Bearer token, the plain equality check would admit the
# request. The input.identity != "" guard prevents this. These tests use an
# empty data.opa_auth_secret to prove denial holds regardless.

test_put_denied_when_both_secret_and_identity_empty if {
	not data.system.authz.allow with input as {
		"method":   "PUT",
		"path":     ["v1", "data", "policies"],
		"identity": "",
	} with data.opa_auth_secret as ""
}

test_patch_denied_when_both_secret_and_identity_empty if {
	not data.system.authz.allow with input as {
		"method":   "PATCH",
		"path":     ["v1", "data", "authn"],
		"identity": "",
	} with data.opa_auth_secret as ""
}

# ── Reads stay closed ────────────────────────────────────────────────────────

test_get_m2m_denied if {
	not allowed({"method": "GET", "path": ["v1", "data", "m2m"]})
}

test_get_pips_denied if {
	not allowed({"method": "GET", "path": ["v1", "data", "pips"]})
}

test_get_authorize_denied if {
	not allowed({"method": "GET", "path": ["v1", "data", "authorize"]})
}

# A read is a read even with the write credential: nothing grants GET.
test_get_m2m_denied_even_with_identity if {
	not allowed({"method": "GET", "path": ["v1", "data", "m2m"], "identity": secret})
}

# ── Other methods on the canonical path ──────────────────────────────────────

test_delete_denied if {
	not allowed({"method": "DELETE", "path": ["v1", "data", "pips"], "identity": secret})
}

test_post_other_data_path_denied if {
	not allowed({"method": "POST", "path": ["v1", "data", "pips"]})
}
