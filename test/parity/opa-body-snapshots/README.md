# OPA-Native Canonical Authorize Body Snapshots

This directory holds the **authoritative target shape** of the body OPA
receives on `POST /v1/data/authorize` after the canonical contract
rebase landed by [authz-agent-ADR-0062](../../../docs/decisions/20260602-authz-agent-adr-0062-canonical-opa-direct-envoy-parity.md).

After the rebase, the canonical client wire-shape **is** the body OPA
receives. Both transports — `POST /access/v1/authorize` through Envoy
and `POST /v1/data/authorize` direct to OPA — send the same bytes.
These snapshots are the single source of truth that:

1. the canonical request DTOs in every SDK (shared Java, Spring,
   Quarkus, Go, Fiber, Gin) MUST serialise byte-identical on the wire
   (see the archived parity handover);
2. the integration parity test (Step 11) asserts the agent receives
   on both transports;
3. the Rego two-package restructure (Step 4) verifies against —
   `opa eval 'data.authorize' --input <snapshot>` must return today's
   canonical response object, and `opa eval 'data.authorize.result'
   --input <snapshot>` must return undefined (the legacy sub-path is
   no longer mounted post-ADR-0062).

## Files

Snapshots are named after the source scenario they derive from —
either a canonical unit-test fixture under
`policies/fixtures/authorize/` (rls-* and multi-resource
families) or a named integration-test step under
`test/integration/testify/` (pip-resolved, token-bound,
wildcard-access families, which lack a canonical unit fixture for the
top-level entrypoint). Each snapshot covers one scenario family the
parent task calls out:

| Snapshot | Source fixture | Scenario family |
| --- | --- | --- |
| [canonical_rls_true_allow_with_predicate.json](canonical_rls_true_allow_with_predicate.json) | `canonical_rls_true_allow_with_predicate/input.json` | **allow** with RLS-driven `predicates[]` |
| [canonical_rls_true_ols_deny_short_circuit.json](canonical_rls_true_ols_deny_short_circuit.json) | `canonical_rls_true_ols_deny_short_circuit/input.json` | **deny** via OLS short-circuit |
| [canonical_rls_true_ols_allow_but_rls_deny.json](canonical_rls_true_ols_allow_but_rls_deny.json) | `canonical_rls_true_ols_allow_but_rls_deny/input.json` | **deny** via RLS post-OLS-allow |
| [canonical_rls_default_true_when_omitted.json](canonical_rls_default_true_when_omitted.json) | `canonical_rls_default_true_when_omitted/input.json` | **rls-default-on** (omitted `ignoreRls` ⇒ RLS evaluated) |
| [canonical_multi_resource_order_preserved.json](canonical_multi_resource_order_preserved.json) | `canonical_multi_resource_order_preserved/input.json` | **rls-ignored** (`ignoreRls: true`) plus multi-resource order preservation |
| [canonical_pip_resolved_customer_read.json](canonical_pip_resolved_customer_read.json) | `test/integration/testify/authorize_test.go::authorize.predicate_pip_value_substituted` | **pip-resolved** (subject-attribute PIP substituted into RSQL predicate) |
| [canonical_token_bound_alias_in_predicate.json](canonical_token_bound_alias_in_predicate.json) | `test/integration/testify/pip_admin_test.go::token_pip_authorize.positive_alias_in_predicate` | **token-bound** (token-claim alias substituted into RSQL predicate) |
| [canonical_wildcard_access_all_all.json](canonical_wildcard_access_all_all.json) | `test/integration/testify/wildcard_access_test.go::wildcard_access.all_all.admin_allow_any` | **wildcard-access** (ALL/ALL grant short-circuits to ALLOW with no predicates) |

The pip-resolved, token-bound, and wildcard-access snapshots do not
have a canonical unit-test `input.json` source (those families live in
`policies/fixtures/wildcard_access/` and
`policies/fixtures/pip/` which exercise sub-package compute
rules, not the top-level `data.authorize` entrypoint); they were
synthesised by hand from the named integration-test scenarios using
the methodology below. The integration parity test (Step 11 of the
parent task) is the cross-check that asserts every snapshot here is
the byte-identical body OPA actually receives at runtime.

## Synthesis methodology

Each snapshot is the byte-identical result of the canonical client request body
as it arrives at OPA's `POST /v1/data/authorize` endpoint. Following
[authz-agent-ADR-0062](../../../docs/decisions/20260602-authz-agent-adr-0062-canonical-opa-direct-envoy-parity.md),
the `/access/v1/authorize` canonical route is **pure routing** with zero body
mutation — Envoy applies no Lua transform on that route (ADR-0062 Decision 5). The body the client
sends is therefore byte-identical to the body OPA receives, making the snapshots
computable directly from the canonical request fixtures without running a stack.
The (R/D) audit table in the parent task *Decisions* section classifies every
field. The transform is deterministic, so the snapshots are computed inline
rather than captured from a running stack:

1. Wrap the request in the OPA Data API envelope: `{"input": {...}}`.
2. **(R) row 2** — `authorizationToken`: the snapshot encodes a
   placeholder Bearer string of the form
   `Bearer <test-jwt-for-{subjectTokenRef}>` so the snapshot is
   independent of test-realm token rotation. The integration parity
   test (Step 11) substitutes a real JWT signed by the runtime
   Keycloak realm at run time.
3. **(R) row 3** — `authorizationType`: empty string (no SDK consumer
   sets a non-empty type today; matches the production default).
4. **(R) row 4** — `requestHeaders`: empty object. The SDK test
   harness does not propagate ambient HTTP headers into this map;
   the integration parity test (Step 11) confirms this remains the
   shape OPA actually receives.
5. **`decisionLogPipTrace` is retired** (authz-agent-ADR-0063): the
   canonical body no longer carries this flag. PIP resolution context
   is no longer surfaced on the request or response — it is captured
   only in the decision log via OPA-native `nd_builtin_cache`. The Lua
   filters no longer inject the field; the snapshots omit it.
6. Inline the existing canonical request body fields verbatim
   (`resources`, `ignoreRls`, etc.). The `subjectTokenRef` field is
   **translated** into a `subject` field of the form
   `Bearer <test-jwt-for-{subjectTokenRef}>` (same placeholder used by
   `authorizationToken`). This mirrors today's wire shape: the
   production Java/Quarkus/Go canonical client sends a `subject` field
   carrying the Bearer string, and the Lua filter pipes it through to
   OPA verbatim alongside the injected `authorizationToken`. Identity
   resolution lives in `data.identity.authenticate(input)` which
   reads `input.subject` — D6 freezes that compute path, so the wire
   shape must continue to carry `subject` for the canonical-response
   branch to fire. The `_can_reuse_admission_subject` optimisation
   then short-circuits the second token validation because
   `subject == authorizationToken`.

The integration parity test in Step 11 is the source of cross-check
truth: it MUST POST the same body to both transports and assert
byte-identical reception, and it MUST exercise at least one snapshot
per scenario family above.

## How to refresh

If the canonical Lua transform changes (forbidden by D6 except via a
follow-on ADR) or the existing canonical fixtures gain new fields,
update each snapshot to match. The transform is reproducible by hand
from the audit table; no runtime stack is required. Run
`bash tests/parity/scripts/run-parity-suite.sh` (PARITY_PROFILE=authz-agent)
after editing to confirm the integration parity test still asserts
byte-equality.

## Living constraints

- **D6** — the OPA-received body shape is frozen. Adding or
  reshaping fields in this directory requires a superseding ADR.
- **ADR-0049 token-isolation** — `requestHeaders` MUST NOT carry the
  inbound `Authorization` or `incoming-token` header values, even
  empty. Every snapshot here uses `requestHeaders: {}` and the SDK
  documentation enforces the skip-list at the consumer boundary.
- **No `subjectTokenRef`** — the unit-test shorthand is not part of
  the OPA-native wire shape and must not appear in any snapshot.
