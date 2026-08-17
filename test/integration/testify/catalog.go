// Copyright 2024-2026 Netcracker Technology Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package runtimetest

// StepEntry describes a single named integration test step.
type StepEntry struct {
	Name       string
	Username   string
	Endpoint   string
	Resource   string
	Operation  string
	TokenRoles string
}

// Catalog is the machine-readable source of truth for all runtime integration test steps.
// Every executed step must reference a name from this catalog; the catalog also drives
// the committed human-readable table in tests/readme.md.
//
// Username convention: use the actual Keycloak username for steps that authenticate as a
// specific user; use "n/a" when no end-user identity exists (no token, service tokens,
// setup actions without user context).
var Catalog = []StepEntry{
	// ── setup ────────────────────────────────────────────────────────────
	{"setup.wait_for_keycloak", "n/a", "GET (Keycloak OIDC discovery)", "-", "-", "none"},
	{"setup.token_acquire_expired", "order-reader, admin", "POST (Keycloak /token)", "-", "-", "ROLE_ORDER_MANAGEMENT_RO_USER, ROLE_ADMINISTRATOR"},
	{"setup.token_expiry_wait", "n/a", "-", "-", "-", "none"},
	{"setup.token_acquire_valid", "order-reader, admin", "POST (Keycloak /token)", "-", "-", "ROLE_ORDER_MANAGEMENT_RO_USER, ROLE_ADMINISTRATOR"},
	{"setup.wait_for_authz_policy_admin", "n/a", "GET /authz-policy-admin/hash", "-", "-", "none"},
	{"setup.policy_upload", "n/a", "PUT /access/v1/simplifiedPolicies/domainPolicies/{domain}", "-", "-", "none"},
	{"setup.pip_upload", "n/a", "PUT /access/v1/simplifiedPolicies/domainPIPs/{domain}", "-", "-", "none"},
	{"setup.wait_for_agent", "admin", "POST /access/v1/check/resource", "-", "-", "ROLE_ADMINISTRATOR"},

	// ── authorize ────────────────────────────────────────────────────────
	{"authorize.order_read.rls_true.deny", "order-reader", "POST /access/v1/authorize", "ORDER", "READ", "ROLE_ORDER_MANAGEMENT_RO_USER"},
	{"authorize.order_read.response_structure", "admin", "POST /access/v1/authorize", "ORDER", "READ", "ROLE_ADMINISTRATOR"},
	{"authorize.public_doc_read.rls_default.allow", "admin", "POST /access/v1/authorize", "PUBLIC_DOC", "READ", "ROLE_ADMINISTRATOR"},
	{"authorize.multi_resource.order_preserved", "order-reader", "POST /access/v1/authorize", "ORDER,ATTACHMENT", "READ", "ROLE_ORDER_MANAGEMENT_RO_USER"},
	{"authorize.no_token.401", "n/a", "POST /access/v1/authorize", "ORDER", "READ", "none"},
	{"authorize.expired_token.401", "order-reader", "POST /access/v1/authorize", "ORDER", "READ", "ROLE_ORDER_MANAGEMENT_RO_USER (expired)"},
	{"authorize.invalid_token.401", "n/a", "POST /access/v1/authorize", "ORDER", "READ", "none (invalid)"},
	{"authorize.naked_authorization_token.401", "admin", "POST /access/v1/authorize", "ORDER", "READ", "ROLE_ADMINISTRATOR"},
	{"authorize.naked_subject_token.deny", "admin", "POST /access/v1/authorize", "ORDER", "READ", "ROLE_ADMINISTRATOR"},
	{"authorize.missing_subject.401", "n/a", "POST /access/v1/authorize", "ORDER", "READ", "none"},
	{"authorize.empty_body.401", "n/a", "POST /access/v1/authorize", "-", "-", "none"},
	{"authorize.predicate_subject_attr_substituted", "admin", "POST /access/v1/authorize", "PUBLIC_DOC", "READ", "ROLE_ADMINISTRATOR"},
	{"authorize.predicate_pip_value_substituted", "admin", "POST /access/v1/authorize", "CUSTOMER", "READ", "ROLE_ADMINISTRATOR"},

	// ── check_resource ───────────────────────────────────────────────────
	{"check_resource.order_read.rls_deny", "order-reader", "POST /access/v1/check/resource", "ORDER", "READ", "ROLE_ORDER_MANAGEMENT_RO_USER"},
	{"check_resource.incoming_token_used_for_subject", "order-reader", "POST /access/v1/check/resource", "ORDER", "READ", "ROLE_ORDER_MANAGEMENT_RO_USER"},
	{"check_resource.expired_authorization.401", "order-reader", "POST /access/v1/check/resource", "ATTACHMENT", "READ", "ROLE_ORDER_MANAGEMENT_RO_USER (expired)"},
	{"check_resource.no_token.401", "n/a", "POST /access/v1/check/resource", "ATTACHMENT", "READ", "none"},
	{"check_resource.tenant_id_ignored", "order-reader", "POST /access/v1/check/resource", "ORDER", "READ", "ROLE_ORDER_MANAGEMENT_RO_USER"},
	{"check_resource.tenant_id_absent", "order-reader", "POST /access/v1/check/resource", "ORDER", "READ", "ROLE_ORDER_MANAGEMENT_RO_USER"},
	{"check_resource.null_body.400", "admin", "POST /access/v1/check/resource", "-", "-", "ROLE_ADMINISTRATOR"},
	{"check_resource.boolean_response", "admin", "POST /access/v1/check/resource", "ATTACHMENT", "READ", "ROLE_ADMINISTRATOR"},
	{"check_resource.missing_fields.400", "admin", "POST /access/v1/check/resource", "-", "-", "ROLE_ADMINISTRATOR"},
	{"check_resource.wrong_address.404", "admin", "POST /access/v1/check/resourc", "ATTACHMENT", "READ", "ROLE_ADMINISTRATOR"},
	{"check_resource.incoming_token_precedence_over_authorization", "admin+order-reader", "POST /access/v1/check/resource", "BULK_OPEN", "READ", "ROLE_ADMINISTRATOR (Authorization) / ROLE_ORDER_MANAGEMENT_RO_USER (Incoming-Token)"},
	{"check_resource.anonymous_subject_marker", "admin", "POST /access/v1/check/resource", "BULK_OPEN", "READ", "ROLE_ADMINISTRATOR (M2M) / anonymous (subject)"},
	{"check_resource.incoming_token_stripped_from_header_pip", "admin", "POST /access/v1/check/resource", "ATTACHMENT", "READ", "ROLE_ADMINISTRATOR"},

	// ── check_resource_bulk ──────────────────────────────────────────────
	{"check_resource_bulk.owner_mismatch.denied", "order-reader", "POST /access/v1/check/resource/bulk", "ORDER", "READ", "ROLE_ORDER_MANAGEMENT_RO_USER"},
	{"check_resource_bulk.unknown_type.denied", "admin", "POST /access/v1/check/resource/bulk", "INVOICE", "READ", "ROLE_ADMINISTRATOR"},
	{"check_resource_bulk.empty_array", "admin", "POST /access/v1/check/resource/bulk", "-", "-", "ROLE_ADMINISTRATOR"},
	{"check_resource_bulk.null_body.400", "admin", "POST /access/v1/check/resource/bulk", "-", "-", "ROLE_ADMINISTRATOR"},
	{"check_resource_bulk.response_is_array", "admin", "POST /access/v1/check/resource/bulk", "ORDER", "READ", "ROLE_ADMINISTRATOR"},
	{"check_resource_bulk.large_3000", "admin", "POST /access/v1/check/resource/bulk", "BULK_OPEN", "READ", "ROLE_ADMINISTRATOR"},
	{"check_resource_bulk.no_token.401", "n/a", "POST /access/v1/check/resource/bulk", "ORDER", "READ", "none"},
	{"check_resource_bulk.no_id_empty", "admin", "POST /access/v1/check/resource/bulk", "ORDER", "READ", "ROLE_ADMINISTRATOR"},
	{"check_resource_bulk.missing_type_op.400", "admin", "POST /access/v1/check/resource/bulk", "-", "-", "ROLE_ADMINISTRATOR"},
	{"check_resource_bulk.duplicate_ids.400", "admin", "POST /access/v1/check/resource/bulk", "ORDER", "READ,DELETE", "ROLE_ADMINISTRATOR"},
	{"check_resource_bulk.tenant_id_ignored", "order-reader", "POST /access/v1/check/resource/bulk", "ORDER", "READ", "ROLE_ORDER_MANAGEMENT_RO_USER"},
	{"check_resource_bulk.wrong_address.404", "admin", "POST /access/v1/check/resource/bul", "ORDER", "READ", "ROLE_ADMINISTRATOR"},

	// ── check_filter ─────────────────────────────────────────────────────
	{"check_filter.calculation_result_present", "admin", "POST /access/v1/check/filter", "ORDER", "READ", "ROLE_ADMINISTRATOR"},
	{"check_filter.unknown_type.deny", "admin", "POST /access/v1/check/filter", "NONEXISTENT", "READ", "ROLE_ADMINISTRATOR"},
	{"check_filter.deny_all_fields", "admin", "POST /access/v1/check/filter", "NONEXISTENT", "READ", "ROLE_ADMINISTRATOR"},
	{"check_filter.known_resource.not_null", "order-reader", "POST /access/v1/check/filter", "ATTACHMENT", "READ", "ROLE_ORDER_MANAGEMENT_RO_USER"},
	{"check_filter.missing_operation", "order-reader", "POST /access/v1/check/filter", "ATTACHMENT", "-", "ROLE_ORDER_MANAGEMENT_RO_USER"},
	{"check_filter.tenant_id_ignored", "admin", "POST /access/v1/check/filter", "NONEXISTENT", "READ", "ROLE_ADMINISTRATOR"},
	{"check_filter.no_token.401", "n/a", "POST /access/v1/check/filter", "ORDER", "READ", "none"},
	{"check_filter.missing_resource_type.400", "admin", "POST /access/v1/check/filter", "-", "READ", "ROLE_ADMINISTRATOR"},
	{"check_filter.wrong_address.404", "admin", "POST /access/v1/check/filte", "ORDER", "READ", "ROLE_ADMINISTRATOR"},

	// ── pip_general ─────────────────────────────────────────────────────
	{"pip_general.stub_reset", "n/a", "POST (pip-stub reset)", "-", "-", "none"},
	{"pip_general.upload_pips_for_general", "n/a", "PUT /access/v1/simplifiedPolicies/domainPIPs/{domain}", "CUSTOMER", "READ", "none"},
	{"pip_general.active_pip_called", "admin", "POST /access/v1/check/filter", "CUSTOMER", "READ", "ROLE_ADMINISTRATOR"},
	{"pip_general.stub_verify_active_called", "n/a", "GET (pip-stub /calls)", "CUSTOMER", "READ", "none"},
	{"pip_general.stub_reset_after", "n/a", "POST (pip-stub reset)", "-", "-", "none"},
	{"pip_general.inactive_pip_not_called", "admin", "POST /access/v1/check/filter", "DOCUMENT", "READ", "ROLE_ADMINISTRATOR"},
	{"pip_general.stub_verify_inactive_not_called", "n/a", "GET (pip-stub /calls)", "DOCUMENT", "READ", "none"},
	{"pip_general.bulk_reset_calls", "n/a", "POST (pip-stub reset)", "-", "-", "none"},
	{"pip_general.bulk_pin_allowed_subset", "n/a", "PUT (pip-stub configure)", "-", "-", "none"},
	{"pip_general.bulk_pip_filters_resources", "admin", "POST /access/v1/check/resource/bulk", "CUSTOMER", "READ", "ROLE_ADMINISTRATOR"},
	{"pip_general.bulk_stub_verify_called", "n/a", "GET (pip-stub /calls)", "CUSTOMER", "READ", "none"},
	{"pip_general.restore_default_stub", "n/a", "PUT (pip-stub configure)", "-", "-", "none"},

	// ── pip_jsonpath (D-AF-U) ──────────────────────────────────────────
	{"pip_jsonpath.stub_reset", "n/a", "POST (pip-stub reset)", "-", "-", "none"},
	{"pip_jsonpath.upload_json_pip", "n/a", "PUT /access/v1/simplifiedPolicies/domainPIPs/{domain}", "CUSTOMER", "READ", "none"},
	{"pip_jsonpath.pin_json_response", "n/a", "PUT (pip-stub configure)", "-", "-", "none"},
	{"pip_jsonpath.bulk_extracts_ids_and_filters", "admin", "POST /access/v1/check/resource/bulk", "CUSTOMER", "READ", "ROLE_ADMINISTRATOR"},
	{"pip_jsonpath.restore_legacy_pip", "n/a", "PUT /access/v1/simplifiedPolicies/domainPIPs/{domain}", "CUSTOMER", "READ", "none"},
	{"pip_jsonpath.restore_default_stub", "n/a", "PUT (pip-stub configure)", "-", "-", "none"},

	// ── rls_aggregation ──────────────────────────────────────────────────
	{"authorize.multi_frag.rls_or_aggregation", "admin", "POST /access/v1/authorize", "MULTI_FRAG_ITEM", "READ", "ROLE_ADMINISTRATOR"},
	{"check_filter.multi_frag.rsql_or_aggregation", "admin", "POST /access/v1/check/filter", "MULTI_FRAG_ITEM", "READ", "ROLE_ADMINISTRATOR"},

	// ── token_pip_authorize (ADR-0046) ─────────────────────────────────
	{"token_pip_authorize.upload_token_pips", "n/a", "PUT /access/v1/simplifiedPolicies/domainPIPs/{domain}", "TOKEN_PIP_POSITIVE,TOKEN_PIP_DEFAULT", "READ", "none"},
	{"token_pip_authorize.positive_alias_in_predicate", "admin", "POST /access/v1/authorize", "TOKEN_PIP_POSITIVE", "READ", "ROLE_ADMINISTRATOR"},
	{"token_pip_authorize.default_value_fallback", "admin", "POST /access/v1/authorize", "TOKEN_PIP_DEFAULT", "READ", "ROLE_ADMINISTRATOR"},

	// ── pip_deny_reason ─────────────────────────────────────────────────
	{"pip_deny.upload_broken_pip", "n/a", "PUT /access/v1/simplifiedPolicies/domainPIPs/{domain}", "PIP_FAIL_TEST", "READ", "none"},
	{"pip_deny.pip_failure_deny_reason", "admin", "POST /access/v1/authorize", "PIP_FAIL_TEST", "READ", "ROLE_ADMINISTRATOR"},
	{"pip_deny.missing_attr_deny_reason", "admin", "POST /access/v1/authorize", "ATTR_MISS_TEST", "READ", "ROLE_ADMINISTRATOR"},

	// ── health ───────────────────────────────────────────────────────────
	{"health.healthy_strict", "n/a", "GET /health", "-", "-", "none"},
	{"health.healthy_permissive.degraded", "n/a", "GET /health (degraded permissive)", "-", "-", "none"},
	{"health.unhealthy.strict_partial", "n/a", "GET /health (degraded strict)", "-", "-", "none"},
	{"health.method_not_allowed", "n/a", "POST /health", "-", "-", "none"},
	{"health.regression.check_resource", "admin", "POST /access/v1/check/resource", "ATTACHMENT", "READ", "ROLE_ADMINISTRATOR"},
	{"health.compose_wiring", "n/a", "GET /health", "-", "-", "none"},
	// readiness: pap-client healthcheck --readiness must exit 0 after the
	// first successful policy pull (pull status latch written).
	{"readiness.policies_loaded_after_pull", "n/a", "pap-client healthcheck --readiness (docker exec)", "-", "-", "none"},

	// ── decision_logs ────────────────────────────────────────────────────
	{"decision_logs.download_no_token.200", "n/a", "GET /internal/v1/decision-logs", "-", "-", "none"},
	{"decision_logs.content_is_ndjson", "n/a", "GET /internal/v1/decision-logs", "-", "-", "none"},

	// ── entitlements (ADR-0054 / D-AG-15) ────────────────────────────────
	// Exercises the container-pinned entitlements PIP end-to-end: the test
	// pins a per-user response on the entitlements-mock stub, uploads an
	// ENT-flavoured policy via PUT /access/v1/simplifiedPolicies/domainPolicies/{domain} (pull loop), then drives
	// /access/v1/check/resource through Envoy + OPA to validate that the
	// ENT operand evaluates against the resolved bucket.
	{"entitlements.contains.allow_hit", "admin", "POST /access/v1/check/resource", "ENT_CONTRACT", "READ", "ROLE_ADMINISTRATOR"},
	{"entitlements.contains.deny_miss", "admin", "POST /access/v1/check/resource", "ENT_CONTRACT", "READ", "ROLE_ADMINISTRATOR"},
	{"entitlements.is_empty.allow_when_empty", "admin", "POST /access/v1/check/resource", "ENT_EMPTY", "READ", "ROLE_ADMINISTRATOR"},
	{"entitlements.multi_as_union.allow", "admin", "POST /access/v1/check/resource", "ENT_MULTI", "READ", "ROLE_ADMINISTRATOR"},
	{"decision_logs.catalog_coverage", "n/a", "GET /internal/v1/decision-logs", "-", "-", "none"},
	{"decision_logs.canonical_path_header", "admin", "POST /access/v1/authorize", "ORDER", "READ", "ROLE_ADMINISTRATOR"},
	{"decision_logs.legacy_path_header", "admin", "POST /access/v1/check/resource", "ATTACHMENT", "READ", "ROLE_ADMINISTRATOR"},

	// ── opa_request_parity (ADR-0032) ───────────────────────────────────
	{"parity.capture_reset", "n/a", "POST (upstream-capture reset)", "-", "-", "none"},
	{"parity.single_resource", "admin", "POST /access/v1/authorize + POST /access/v1/check/resource", "ATTACHMENT", "READ", "ROLE_ADMINISTRATOR"},
	{"parity.bulk", "admin", "POST /access/v1/authorize + POST /access/v1/check/resource/bulk", "ATTACHMENT", "READ", "ROLE_ADMINISTRATOR"},
	{"parity.filter", "admin", "POST /access/v1/authorize + POST /access/v1/check/filter", "ORDER", "READ", "ROLE_ADMINISTRATOR"},
	{"parity.response_envelope_shape", "admin", "POST /access/v1/authorize", "ATTACHMENT", "READ", "ROLE_ADMINISTRATOR"},
	{"parity.original_path_no_effect", "admin", "POST /access/v1/authorize (x2)", "ATTACHMENT", "READ", "ROLE_ADMINISTRATOR"},
	{"authorize.envoy_opa_direct.bytewise_response_parity", "admin", "POST /access/v1/authorize (Envoy + OPA-direct)", "ORDER", "READ", "ROLE_ADMINISTRATOR"},

	// ── wildcard_access (ADR-0040) ──────────────────────────────────────
	{"wildcard_access.upload_wildcard_policies", "n/a", "PUT /access/v1/simplifiedPolicies/domainPolicies/{domain}", "-", "-", "none"},
	{"wildcard_access.all_all.admin_allow_any", "admin", "POST /access/v1/authorize", "UNKNOWN_TYPE", "DELETE", "ROLE_ADMINISTRATOR"},
	{"wildcard_access.all_all.no_predicates", "admin", "POST /access/v1/authorize", "ORDER", "READ", "ROLE_ADMINISTRATOR"},
	{"wildcard_access.all_all.no_deny_reason", "admin", "POST /access/v1/authorize", "WC_EXACT_ONLY", "READ", "ROLE_ADMINISTRATOR"},
	{"wildcard_access.all_op.reader_read_any_rt", "order-reader", "POST /access/v1/authorize", "UNKNOWN_TYPE", "READ", "ROLE_ORDER_MANAGEMENT_RO_USER"},
	{"wildcard_access.all_op.reader_delete_denied", "order-reader", "POST /access/v1/authorize", "UNKNOWN_TYPE", "DELETE", "ROLE_ORDER_MANAGEMENT_RO_USER"},
	{"wildcard_access.rt_all.reader_any_op", "order-reader", "POST /access/v1/authorize", "WC_RT_TARGET", "DELETE", "ROLE_ORDER_MANAGEMENT_RO_USER"},
	{"wildcard_access.rt_all.reader_other_rt_denied", "order-reader", "POST /access/v1/authorize", "OTHER_TYPE", "DELETE", "ROLE_ORDER_MANAGEMENT_RO_USER"},
	{"wildcard_access.mixed.partial_wildcard", "order-reader", "POST /access/v1/authorize", "WC_RT_TARGET,INVOICE", "DELETE,READ", "ROLE_ORDER_MANAGEMENT_RO_USER"},
	{"wildcard_access.legacy.check_resource_all_all", "admin", "POST /access/v1/check/resource", "UNKNOWN_TYPE", "DELETE", "ROLE_ADMINISTRATOR"},
	{"wildcard_access.legacy.check_resource_bulk_all_all", "admin", "POST /access/v1/check/resource/bulk", "UNKNOWN_TYPE", "DELETE", "ROLE_ADMINISTRATOR"},
	{"wildcard_access.legacy.check_filter_all_op", "order-reader", "POST /access/v1/check/filter", "UNKNOWN_TYPE", "READ", "ROLE_ORDER_MANAGEMENT_RO_USER"},
	{"wildcard_access.restore_original_policies", "n/a", "PUT /access/v1/simplifiedPolicies/domainPolicies/{domain}", "-", "-", "none"},

	// ── m2m_keycloak (Step 15) ──────────────────────────────────────────
	// These steps run only when M2M_KEYCLOAK_PROFILE=true (activated by
	// docker-compose.m2m-keycloak.yml overlay). In the default static-token
	// profile they are skipped — the step body calls t.Skip() so the
	// catalog coverage check still passes.
	{"m2m_keycloak.pull_succeeds_with_keycloak_token", "admin", "POST /access/v1/check/resource", "ATTACHMENT", "READ", "ROLE_ADMINISTRATOR"},
	{"m2m_keycloak.agent_functional_after_token_refresh", "admin", "POST /access/v1/check/resource", "ATTACHMENT", "READ", "ROLE_ADMINISTRATOR"},

	// ── opa_lockdown (Step 14 / ADR-0077) ───────────────────────────────
	// Validates that --authorization=basic + --authentication=token +
	// system_authz.rego block unauthenticated reads and writes while allowing
	// authenticated writes (pap-client's OPA bearer token).
	// POST /v1/data/authorize → 200 is covered by
	// authorize.envoy_opa_direct.bytewise_response_parity.
	{"opa_lockdown.authorize_explain_forbidden.401", "n/a", "POST /v1/data/authorize?explain=full (OPA-direct)", "-", "-", "none"},
	{"opa_lockdown.authorize_plain_still_open.200", "n/a", "POST /v1/data/authorize (OPA-direct, no params)", "-", "-", "none"},
	{"opa_lockdown.m2m_get_forbidden.403", "n/a", "GET /v1/data/m2m (OPA-direct)", "-", "-", "none"},
	{"opa_lockdown.pips_get_forbidden.403", "n/a", "GET /v1/data/pips (OPA-direct)", "-", "-", "none"},
	{"opa_lockdown.write_without_auth.401", "n/a", "PUT /v1/data/opa-lockdown-test (OPA-direct, no auth)", "-", "-", "none"},
	{"opa_lockdown.write_with_auth.204", "n/a", "PUT /v1/data/opa-lockdown-test (OPA-direct, with token)", "-", "-", "none"},

	// ── opa_restart (restart survival) ──────────────────────────────────
	// Verifies that policies, PIPs, and authentication data survive an OPA
	// container restart. pap-client writes all document roots to the shared
	// opa-data volume before pushing to OPA's Data API; on restart OPA
	// reloads from disk so correct decisions are served immediately without
	// waiting for the next pap-client push tick (ADR-0077 §Restart).
	{"opa_restart.pre_restart_baseline", "admin", "POST /access/v1/check/resource", "ATTACHMENT", "READ", "ROLE_ADMINISTRATOR"},
	{"opa_restart.restart_opa_container", "n/a", "docker compose restart opa", "-", "-", "none"},
	{"opa_restart.wait_opa_healthy", "n/a", "GET /health (OPA direct)", "-", "-", "none"},
	{"opa_restart.restart_pap_client", "n/a", "docker compose restart pap-client", "-", "-", "none"},
	{"opa_restart.wait_pap_client_healthy", "n/a", "GET /health (pap-client)", "-", "-", "none"},
	{"opa_restart.post_restart_decisions_correct", "admin", "POST /access/v1/check/resource", "ATTACHMENT", "READ", "ROLE_ADMINISTRATOR"},

	// ── opa_mount_restart (mount-mode restart survival) ─────────────────
	// Verifies that the disk files written by pap-client have the correct
	// OPA data-dir layout for restart recovery in ConfigMap-mount mode.
	// In mount mode (MountWatcher) pap-client does NOT republish to OPA
	// when the ConfigMap content is unchanged — disk loading is the ONLY
	// recovery mechanism on OPA restart. This is the worst case.
	// Red proof: removing the disk-write from MountWatcher (or PolicyPuller)
	// causes these checks to fail (file absent or wrong top-level key).
	{"opa_mount_restart.verify_policies_disk_key", "n/a", "docker compose exec pap-client cat /etc/opa/data/policies.json", "-", "-", "none"},
	{"opa_mount_restart.verify_pips_disk_key", "n/a", "docker compose exec pap-client cat /etc/opa/data/pips.json", "-", "-", "none"},
	{"opa_mount_restart.verify_m2m_disk_key", "n/a", "docker compose exec pap-client cat /etc/opa/data/m2m.json", "-", "-", "none"},

	// ── route_security ───────────────────────────────────────────────────
	{"route_security.authorize_hidden.404", "admin", "POST /authorize", "ORDER", "READ", "ROLE_ADMINISTRATOR"},
	{"route_security.v1_data_authorize_hidden.404", "admin", "POST /v1/data/authorize", "ORDER", "READ", "ROLE_ADMINISTRATOR"},
	{"route_security.v1_data_authorize_result_hidden.404", "admin", "POST /v1/data/authorize/result", "ORDER", "READ", "ROLE_ADMINISTRATOR"},
	{"route_security.unknown_path.404", "n/a", "GET /unknown/endpoint", "-", "-", "none"},
	{"route_security.v2_check_resource.implemented", "admin", "POST /access/v2/check/resource", "ORDER", "READ", "ROLE_ADMINISTRATOR"},
	{"route_security.v1_bulk_operations.implemented", "admin", "POST /access/v1/check/resource/bulk/operations", "ORDER", "READ", "ROLE_ADMINISTRATOR"},
	{"route_security.v2_bulk_operations.implemented", "admin", "POST /access/v2/check/resource/bulk/operations", "ORDER", "READ", "ROLE_ADMINISTRATOR"},
	{"route_security.v2_check_filter.implemented", "admin", "POST /access/v2/check/filter", "ORDER", "READ", "ROLE_ADMINISTRATOR"},
	{"route_security.api_version.static", "n/a", "GET /api-version", "-", "-", "none"},
}

// CatalogByName provides O(1) lookup by step name.
var CatalogByName map[string]StepEntry

func init() {
	CatalogByName = make(map[string]StepEntry, len(Catalog))
	seen := make(map[string]bool, len(Catalog))
	for _, e := range Catalog {
		if seen[e.Name] {
			panic("duplicate step name in catalog: " + e.Name)
		}
		seen[e.Name] = true
		CatalogByName[e.Name] = e
	}
}
