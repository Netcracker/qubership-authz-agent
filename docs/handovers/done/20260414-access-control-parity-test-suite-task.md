# Task: 20260414 — Access Control Parity Integration-Test Suite (Legacy Baseline)

*Archived internal engineering document, restored for reference. Component names and paths reflect the tree at the time of writing and may differ from the current layout.*

## Filename

`20260414-access-control-parity-test-suite-task.md`

## Plan

20260413-access-control-parity-testing-plan.md
(Step 3 — Integration-test suite against legacy baseline)

## Jira dev task

*TBD.*

## Status

*TBD.*

## Goal

### Execution Prompt

This section is the task-specific prompt for whoever picks up the handover. Generic
repository rules (pre-read list, markdown discipline, evidence discipline, ADR policy,
delivery format) live in the companion prompt file
20260414-access-control-parity-test-suite-task.prompt.md
and must be read before starting.

### One-sentence mission

Build a deterministic, locally-runnable integration-test suite under
`tests/parity/suite/` that drives the 10 in-parity endpoints from the parity contract
against the **legacy `access-control`** reference stack brought up by Step 2, uses the
unmodified `access-control-spring-libs/access-control-client/` thin-client JAR per
**D4**, captures the deserialized legacy-baseline responses to golden files under
`tests/parity/suite/testdata/golden/` so that Step 4 can re-assert the same
fixtures against Authz Agent without re-running the legacy stack, and exercises every
scenario class the parity contract mandates (OLS allow/deny, RLS filter with typed
predicates, RLS predicate/condition, TOKEN / HEADER / GENERAL PIP-backed conditions,
condition-language operator coverage, multi-row policy combining /
OR-aggregation, PIP-value template substitution into predicate strings,
entitlements PIP coverage against a mocked aggregator,
`Incoming-Token` non-anonymous flows, and `Authorization-Type: anonymous` flows)
across v1 and v2 surfaces — with **no production code changes** to Authz Agent.
Per **D-A** and **D-V** the suite is a **Go + testify** module; it reimplements
the thin-client wire protocol directly in Go per the transport-convention
inventory from Phase 1, rather than calling the Java thin-client JAR. Per **D-W**
the task is considered done only when all 83 tests are green and all golden
files are committed. Wildcard-role fast-path coverage is intentionally out of
scope per **D-S** because legacy `access-control` simplified-policy format has
no role-level wildcard construct.

### Phased execution

Work through these phases in order. Do not skip ahead. After each phase, update the
`Done` checklist below.

1. **Phase 0 — Orientation.** Read the pre-read list in the companion prompt file,
   plus the parity contract
   ../parity/access-control-client-api-surface.md,
   the parent plan, the Step 2 handover
   20260413-access-control-reference-stack-task.md
   (for the exact layout of the legacy stack, its seeded fixtures, the mock PIP
   service control surface, and the identity-provider realm shape), and
   ADR-0049
   (for background on the `Incoming-Token` relay path — Step 3 only runs the suite
   against the legacy stack, but the test fixtures must be designed with Step 4 in
   mind so the same fixtures can be re-pointed at Authz Agent without edits).
2. **Phase 1 — Transport convention inventory + legacy engine reading.**
   Two parallel reading passes — do **both** before writing any Go code:
   1. **Transport convention inventory (Go-side helper design input).** Per
      **D-A** and **D-V**, the Go suite reimplements the wire protocol
      that the Java thin client speaks, rather than calling the thin
      client itself. Phase 1 reads
      `sample-sources/access-control-spring-libs/access-control-client/`
      and `sample-sources/access-control-java-libs/access-control-policy-decision-point/`
      with a **purely documentary** purpose: for every row of the
      parity-contract Summary Table, produce a fully-specified Go
      struct and HTTP helper plan. Specifically:
      1. For each thin-client `RemoteACCommon.checkResourceV1/V2/filterV1/...`
         callsite (column "Client callsite" of the parity-contract
         Summary Table), document: HTTP method, path template, query
         params (tenant_id, userId, obligations, resourceType,
         operation), headers set (`Authorization`, `Incoming-Token`,
         `Authorization-Type`, `Content-Type`, custom headers via
         `HeadersFilter`), request body JSON shape, response DTO
         field set.
      2. For each legacy response DTO
         (`EvaluationResultImpl`, `OldFilterEvaluationResult`,
         `CheckResourceResponse`, `CheckResourcesResponse`,
         `FilterResponse`, `ApiVersionResponse`,
         `ApiVersionSpec`, `GetDirectUserEntitlementsResponse`,
         `Entitlement`, `EntitlementReference`), record the exact
         Jackson JSON field names, their Java types, and their
         `@JsonInclude` / `@JsonProperty` annotations. The Go struct
         tags reproduce the Jackson field names verbatim; Go types
         follow the Java types (Integer→int, boolean→bool,
         `Set<String>`→[]string, `Map<String,Set<String>>`→map\[string\][]string).
      3. Record every transport convention enumerated in **D-V** items
         1–14 with a concrete file:line citation from the legacy
         source on this Phase 1 pass — do not trust **D-V**'s list
         blindly; the list is a draft that Phase 1 verifies and
         extends with any item that was missed.
      4. Produce the Transport Convention Inventory table under this
         handover's [Transport Convention Inventory](#transport-convention-inventory)
         section — each row cites a concrete symbol in
         `sample-sources/access-control-spring-libs/access-control-client/`
         or `sample-sources/access-control-java-libs/access-control-policy-decision-point/`,
         gives the Go-side helper function name the row maps to, and
         names the Go struct pointer the response deserializes into.
      Do **not** fork or shadow any legacy source — Phase 1 only
      reads. If a wire behavior is undocumented in the legacy source
      and cannot be deduced from thin-client code, record it as an
      Open Question and stop before Phase 2.
   2. **Legacy engine reading.** Independently of the thin-client work, read
      the legacy `access-control` server source under `sample-sources/access-control/`
      to answer the Phase-1 inventory items that multiple Open Questions cite.
      At minimum:
      - **Anonymous subject handling (D-K / row 4).** Grep
        `access-control-app/` for `Authorization-Type` / `"anonymous"` /
        `AnonymousSubject` / equivalent; determine which subject shape the
        server constructs when that header is present (empty principal, M2M
        principal, a dedicated anonymous role bucket, etc.). Record the
        answer under the Transport Convention Inventory table's **Legacy semantics**
        sub-section (add one if it does not exist) so row 4's fixture
        design is grounded, not speculative.
      - **Wildcard-role acceptance (OQ-SUITE-4).** *Already resolved by
        D-S (owner iteration 5)* — legacy simplified-policy format has
        no role-level wildcard construct; the 4 wildcard rows that
        previous catalogue iterations had (PSUITE-2-wildcard,
        PSUITE-4-wildcard, PSUITE-6-wildcard,
        AGG-wildcard-wins-over-predicate) are removed. Phase 1 still
        cross-references the finding against
        SimplifiedPolicyMappingService.java:225-232
        and
        BaseSimplifiedPolicy.java:27
        so the executor can confirm the D-S evidence is still valid on
        a clean checkout; no fixture writing depends on the outcome.
      - **Condition AST grammar (OQ-SUITE-6).** Grep for
        `PolicyConditionEvaluator` / `ConditionParser` /
        `SimplifiedConditionEvaluator` / equivalent; produce a reference
        sheet of accepted operator / keyword spellings
        (`==` vs `=`, `IN (...)` vs `IN[...]`, `CONTAINS ANY`, `null`,
        nested field access, etc.) that Phase 3 uses verbatim when
        writing CLANG fixtures. Fixtures with an unaccepted spelling
        are rejected at seed time with HTTP 400 and block the suite.
      - **Template substitution semantics (OQ-SUITE-9).** Grep for
        `SimplifiedPolicyRenderer` / `PredicateTemplateRenderer` /
        `${subject.` / equivalent; determine whether the legacy server
        even performs `${subject.<alias>}` substitution inside
        `rsqlPredicate` / `sqlFilterCondition` / `mongodbFilterCondition`
        at render time, or whether substitution is a
        **consumer-side** feature (done by the Netcracker Spring libs
        in calling services, not by the `access-control` server
        itself). The answer determines whether the entire SUB block
        (rows 68–75) tests a server-side property or a trivial
        pass-through. **D-T (owner iteration 5) already locked this
        as server-side**, so this Phase 1 item is now down to
        documenting the concrete renderer symbol and its escaping
        rules (OQ-SUITE-9) — not a blocking architectural question
        any more, just an inventory task.
      - **Policy aggregation semantics (OQ-SUITE-8).** Grep for the
        rule aggregator that combines multiple matching policy rows
        (`PolicyRuleAggregator`, `RuleCombiner`, or whatever the
        simplified-policy engine calls it). Determine the combining
        shape for pure OLS row + RLS row on the same
        `(resourceType, operation, role)` locator (AGG row 64). The
        wildcard-row-vs-predicate case that OQ-SUITE-7 tracked is
        out of scope per **D-S** — legacy simplified format has no
        role-level wildcard, so the combining case does not exist.
      - **Mock PIP control surface shape.** Read
        `tests/integration/pipstub/main.go` end-to-end and determine
        the exact JSON schema that `POST /__mock__/responses`
        accepts: path, method, status, body types allowed. D-O assumes
        `{"path": "...", "method": "...", "status": 200, "body": <any
        JSON>}` but this is speculative. If the real shape differs,
        D-O's "extend pipstub additively" fallback kicks in — raise
        an Open Question and stop before editing anything. The same
        check now also covers the EA mock per **D-U**: the control
        surface must accept registrations for the four EA paths
        (`GET /api-version`, `POST /api/v1/entitlements-aggregator/entitlements`,
        `GET /api/v3/user-entitlements/user/{userId}`,
        `GET /api/v3/user-entitlements/user/{userId}/resource-type/{rt}/name/{name}`)
        with response bodies of varying shapes — `Map<String, Map<String, Set<String>>>`,
        a `GetDirectUserEntitlementsResponse` object, and an
        `ApiVersionResponse` object. If pipstub's control surface
        does not support path-templated registrations (the
        `{userId}` etc. wildcards), the executor extends pipstub
        additively to support them, per Step 2 **D-D**, before
        Phase 3 can land the ENT seed pack.
      - **Entitlements wire shape (D-U).** Read
        `sample-sources/entitlements-aggregator/` only enough to
        verify the four endpoint shapes the mock implements actually
        match the real EA. Specifically: confirm the v1 POST request
        body shape (`{"userId": "<id>"}`), the v1 response shape
        (`Map<String, Map<String, Set<String>>>`), the v3
        `GetDirectUserEntitlementsResponse` field set, the
        `Tenant` header convention, and the `/api-version` payload
        format the EA's own controller emits. Cross-reference with
        the legacy AC consumer at
        EntitlementsPipServiceImpl.java:76-201.
        If the real EA serves a wire shape that the mock does not
        replicate (e.g. an extra header, a different status semantic),
        raise it as an Open Question — the mock pinning logic in the
        ENT block must match the real shape, not a guess.
      - **Seed idempotency (OQ-SUITE-5).** Read
        `tests/parity/compose/seed/scripts/seed-access-control.sh` and
        determine whether it guards against re-seeding on subsequent
        boots. Document the finding in Phase 3 so the extended loader
        preserves the same guard discipline.
3. **Phase 2 — Go module bootstrap.** Create a new Go module under
   `tests/parity/suite/` that:
   1. `go mod init <module-path>` with a module path consistent with
      the repo's naming convention (Phase 1 confirms the exact path
      against the existing `tests/integration/testify/go.mod` and
      records it in **D-I**). No dependency on the Java thin-client
      JAR per **D-A** and **D-V**.
   2. Declares direct deps in `go.mod`:
      `github.com/stretchr/testify`, `github.com/google/go-cmp`,
      `github.com/golang-jwt/jwt/v5`. No other external deps — the
      HTTP client is stdlib `net/http`.
   3. Uses the testify Suite pattern (`type ParitySuite struct{ suite.Suite; ... }`)
      matching the layout at
      [tests/integration/testify/suite_test.go](../../../test/integration/testify/suite_test.go).
      `SetupSuite` waits for the Keycloak identity-provider, acquires
      M2M + end-user tokens per **D-N**, and verifies record-mode
      guards per **D-F**.
   4. Loads its configuration from environment variables:
      `PARITY_AC_BASE_URL` (default `http://localhost:${PARITY_AC_PORT:-28090}`),
      `PARITY_IDP_BASE_URL`, `PARITY_M2M_CLIENT_ID`,
      `PARITY_M2M_CLIENT_SECRET`, `PARITY_END_USER_CLIENT_ID`,
      `PARITY_END_USER_CLIENT_SECRET`, `PARITY_PIP_MOCK_CONTROL_URL`,
      `PARITY_EA_MOCK_CONTROL_URL`, `PARITY_TENANT_ID`,
      `PARITY_DOMAIN_NAME`, `PARITY_PROFILE`, `PARITY_GOLDEN_RECORD`.
      The env-var convention matches Step 2's existing
      `PARITY_*` prefix discipline. Step 4 re-points the suite at
      Authz Agent by flipping `PARITY_AC_BASE_URL` and `PARITY_PROFILE`
      alone — test source does not change between profiles.
   5. Declares a `//go:build integration` build tag at the top of
      every test file so `go test ./...` from the repo root does not
      accidentally run the parity tests. Matches the
      `tests/integration/testify/` build-tag convention.
   6. Produces a file layout like:

      ```text
      tests/parity/suite/
        go.mod
        go.sum
        suite_test.go          # ParitySuite + TestParitySuite entry
        catalog.go             # ParityEndpointId enum + row metadata
        helpers.go             # Keycloak tokens, HTTP client, headers
        compare.go             # GoldenComparator (per D-M)
        record.go              # record-mode writer (per D-F)
        pip_control.go         # pip-mock + entitlements-mock control
        model/
          api_version.go       # ApiVersionResponse, ApiVersionSpec
          check_resource.go    # CheckResourceResponse, CheckAccessRequest
          check_resources.go   # CheckResourcesResponse, ...RequestEntry
          filter.go            # OldFilterEvaluationResult, FilterResponse
          entitlements.go      # GetDirectUserEntitlementsResponse, ...
        test_row01_api_version_test.go
        test_row02_check_resource_v1_test.go
        test_row02_fixture_cases_test.go
        test_row02_clang_additional_cases_test.go
        test_row02_agg_additional_cases_test.go
        test_row02_entitlement_cases_test.go
        ...
        test_row10_fixture_cases_test.go
        testdata/
          golden/
            api-version/m2m.json
            check-resource-v1/allow-incoming.json
            ...
      ```

      The exact filename taxonomy is per-row rather than per-block: CLANG /
      AGG / SUB / ENT slices live next to the parity-contract row they reuse
      fixtures from, which proved easier to maintain than the earlier
      `condition_language_test.go` / `policy_aggregation_test.go` style split.
   The module must build and `go test ./... -tags integration
   -run ^$` (no matching tests — just compile check) with exit code
   0 before Phase 3 starts writing any fixture. This is the Phase 2
   gate.
4. **Phase 3 — Fixture seed extension.** Extend the Step 2 seed script (or add a
   sibling one under `tests/parity/compose/seed/`) so that, on first boot, the
   legacy `access-control` instance loads **all** policy fixtures the Phase 4 test
   catalogue requires, not just the four bespoke smoke fixtures Step 2 seeds. Per
   **D-L** everything lands in the **single `PARITY` domain** that Step 2 already
   uses — one seed call, one namespace. Per-test isolation is engineered at the
   **request** level by giving every new row a unique `(resourceType, operation,
   role, user)` tuple. Per **D-N** Phase 3 additively extends
   `tests/parity/compose/idp-seed/parity-realm.json` with the fixed set of test
   users (`parity-reader`, `parity-reviewer`, `parity-multi-role`, `parity-other`,
   `parity-anon-baseline`) plus a password-grant-capable `parity-end-user` OAuth2
   client so end-user tokens can be acquired without Keycloak admin REST. The
   `cloud-common` realm from Step 2 Gap 7 / Follow-up 8 is **not** edited.
   This phase must:
   1. Add the expanded fixtures under
      `tests/parity/compose/seed/policies/` (or a sibling subdirectory named
      `suite/`, whichever keeps diffs clean against Step 2) in the same simplified
      policy/PIP JSON format.
   2. Use **scoped `resourceType` names** per **D-L** for every new row so two
      unrelated fixtures never share a `(resourceType, operation)` locator — e.g.
      `PARITY_CLANG_STRING_EQ` for row 49, `PARITY_AGG_PRED_UNION` for row 63,
      `PARITY_SUB_SCALAR_STR` for row 68. AGG rows that intentionally share a
      locator across 2+ rows call that out in their description.
   3. **Do not** seed `roles: ["*"]` rows — per **D-S** legacy `access-control`
      simplified-policy format has no role-level wildcard construct; such rows
      render into a literal-string role target and match nothing.
   4. Include **TOKEN-PIP** declarations that resolve from JWT claims emitted by
      the parity IdP for the users seeded per **D-N**. Required claims at
      minimum: `department` (used by rows 5/25/43/47/71), `tier` (used by row 65
      and the CLANG block). If a claim is not yet emitted, extend the realm seed
      additively — do not replace existing claims.
   5. Include **HEADER-PIP** declarations keyed on a custom header name that is
      not in `ProhibitedHeaders` (no `authorization`, no `tenant`, no
      `incoming-token`) so the thin client's `HeadersFilter` does not strip it.
      The canonical name used by rows 6/26/44/72 is `x-parity-pip-attribute`.
   6. Include **GENERAL-PIP** declarations whose `url` hard-codes
      `http://pip-mock:8090/...` on the Compose network per **D-E** of Step 2.
      Multiple PIP routes are declared (one per return-shape used by the SUB
      block: scalar-string, scalar-number, scalar-boolean, array, dict,
      special-chars) so each test can pin a dedicated response via
      `POST /__mock__/responses` in `SetupTest` per **D-O**.
   7. Keep the four Step 2 smoke fixtures intact so the O6-amended smoke
      compliance check stays 12/12 green per **D-H**. Before O6 this meant
      `smoke.sh`; after O6 it means the Go `SetupSuite` smoke phase emits
      `[paritysuite] smoke phase: 12/12 assertions green` before any test
      method runs.
   8. **Add the `entitlements-mock` compose service per D-U.** This is
      the only Step 3 change to `tests/parity/compose/docker-compose.yml`
      service list. Specifics:
      1. New service block named `entitlements-mock` with
         `image: pip-stub:local` (same tag as `pip-mock`),
         `container_name: parity-entitlements-mock`,
         `networks: [parity]`, healthcheck identical to `pip-mock`,
         host port published as `${PARITY_EA_PORT:-28092}` for direct
         debugging from the host.
      2. On the existing `access-control` service env block, append two
         new entries: `ACCESS_CONTROL_ENTITLEMENTS_AGGREGATOR_URL=http://entitlements-mock:8080`
         (overrides Step 2's `http://idp:8080` fast-fail dummy at
         line 311 of the current compose) and
         `ACCESS_CONTROL_ENTITLEMENTS_CACHE_ENABLED=false`. Both env
         vars are valid for the existing image; they only flip target
         behavior, not boot semantics, so the smoke compliance check
         remains 12/12 green.
      3. **Do not** modify any of the existing services' images,
         healthchecks, or volumes; per **D-H** the Step 2 stack is
         delicate. Only the `access-control` env block is touched, and
         only additively.
      4. Confirm the smoke compliance check stays 12/12 green before
         and after the compose edit (`smoke.sh` historically, the Go
         smoke phase after O6).
   9. **Add ENT-aware policy fixtures + EA mock pin templates** for
      rows 76–83. Each ENT row has:
      1. A simplified-policy JSON file under
         `tests/parity/compose/seed/policies/` (or the `suite/`
         subdirectory) with a unique `resourceType` per **D-L** (e.g.
         `PARITY_ENT_CONTAINS`, `PARITY_ENT_IN_RHS`,
         `PARITY_ENT_MULTI_AS`, `PARITY_ENT_CONTAINS_ANY`,
         `PARITY_ENT_IS_EMPTY`, `PARITY_ENT_NOT_CONTAINS`,
         `PARITY_ENT_MULTI_RT`, `PARITY_ENT_EMPTY_USER`) and a
         `condition` string in the legacy AST grammar. PIP type is
         **not** declared via simplified PIPs — `entitledResources`
         is a built-in legacy-engine construct that resolves through
         `EntitlementsPipServiceImpl`, not through a `subject.<alias>`
         PIP binding. No `*-pips.json` file is needed for ENT rows.
      2. A `ParityMockPipController.pinEntitlements(...)` helper call
         in the `SetupTest` of each ENT test that pins the
         `entitlements-mock` response on the relevant V3 endpoint
         (default) or V1 endpoint (for the V1-fallback subcase).
         The helper resets EA mock state in the suite-wide
         `TearDownTest` per **D-O**. Mock state for `pip-mock` and
         `entitlements-mock` is independent — resets on one do not
         touch the other.
   **Decision D-C (below)** pre-locks that Step 3 does **not** load the
   `sample-sources/simplified-policy-sample/CloudBSS-simplified-policies.json`
   bundle into the legacy stack — the parity suite is driven entirely by bespoke
   fixtures that the suite itself owns end-to-end, and `simplified-policy-sample/`
   stays a schema reference. If the executor discovers a parity-contract row the
   bespoke fixtures genuinely cannot reach without the CloudBSS bundle, escalate
   as an Open Question rather than reopening D-C.
5. **Phase 4 — Test catalogue implementation (Go + testify).** Implement
   the full set of Go tests listed in
   [Planned Test Catalogue](#planned-test-catalogue) below. Each test:
   1. Uses the Go HTTP helper layer from Phase 2 — raw `net/http` calls
      hand-wrapped in functions that enforce the transport conventions
      from **D-V** items 1–14 (Authorization header, Incoming-Token,
      Authorization-Type: anonymous, tenant_id, userId, HeadersFilter
      prohibited-header list, Content-Type, JSON body encoding). The
      helper names match the parity-contract Summary Table client
      callsites one-to-one: `HelperCheckResourceV1(ctx, req, tokens,
      customHeaders)`, `HelperCheckFilterV1(ctx, resourceType,
      operation, tokens, customHeaders)`, etc. Tests never hand-roll
      a request — if a helper does not exist for an endpoint, it's a
      Phase 2 gap, not a test-file fix.
   2. Records the deserialized response in a golden JSON file under
      `tests/parity/suite/testdata/golden/<endpoint>/<fixture>.json`
      per **D-D**. The golden path mirrors the `#` column of the
      parity-contract Summary Table so cross-referencing stays
      mechanical. Golden files are committed.
   3. Asserts on the deserialized golden (per **D1** + **D-M**), **not**
      on raw bytes. For v2 endpoints, the `Obligations` field on the Go
      struct is filtered via `cmpopts.IgnoreFields` so per-run
      `obligations=false` and any residual response obligation key are
      dropped before `cmp.Diff` runs.
   4. Runs in a deterministic order. Testify Suite runs methods in
      alphabetical order by default and does **not** parallelize within
      a suite unless `t.Parallel()` is called — Phase 4 must **not**
      call `t.Parallel()` in any parity test function. Every test's
      `SetupTest` (per **D-O**) pins any GENERAL-PIP or EA response it
      relies on via `POST /__mock__/responses` on `pip-mock` or
      `entitlements-mock` respectively. A suite-wide `TearDownTest`
      resets all pinned responses on both mocks so no state leaks
      across tests. Pin/reset is done via the `pip_control.go` helper
      from Phase 2.
6. **Phase 5 — Golden capture and diff machinery (Go).** Add a small
   `GoldenComparator` helper under `tests/parity/suite/compare.go` that:
   - Reads the existing golden via `os.ReadFile` + `json.Unmarshal` into
     a typed Go struct selected by the parity-contract row id per
     **D-M**'s lookup table.
   - Calls the HTTP helper for the current test, unmarshals the
     response into the same Go struct type, and runs
     `cmp.Diff(golden, actual, cmpopts.SortSlices(stringLess),
     cmpopts.IgnoreFields(..., "Obligations"), optsPerRow...)`.
   - On mismatch, writes the observed response next to the golden with
     a `.observed.json` suffix (pretty-printed), fails the test with
     `t.Errorf("golden mismatch at %s:\n%s", goldenPath, diff)`, and
     does **not** early-exit so multiple mismatches are reported in a
     single run.
   - In **record mode** (`PARITY_GOLDEN_RECORD=1` + `PARITY_PROFILE=legacy`
     per **D-F**), bypasses the comparison step and writes the fresh
     response to the golden path via `os.WriteFile` with `0644` perms
     and pretty JSON formatting (`json.MarshalIndent` with 2-space
     indent). Record mode must fail fast if the profile is anything
     other than `legacy` — the check happens in `SetupSuite` before any
     test runs.
   - Exposes a `HandleRequestIdField` option for rows whose response
     carries a non-deterministic `requestId`-like audit field (if any
     are discovered by Phase 1). Phase 4 must enumerate such fields in
     the comparator code with a one-line justification per entry; the
     minimal ignore-list is just `Obligations` until Phase 1 finds
     something else.
7. **Phase 6 — Suite wrapper script and reporting.** Wire
   `tests/parity/scripts/run-parity-suite.sh` so a single invocation:
   1. Calls `tests/parity/scripts/build-images.sh` if the AC / IdP
      image tags are missing (delegate only — do not duplicate the
      logic).
   2. Runs `docker compose up -d` against
      `tests/parity/compose/docker-compose.yml` and waits for every
      service to reach `healthy` (reuse the same health-wait loop
      `smoke.sh` uses).
   3. Runs `tests/parity/scripts/smoke.sh` as a pre-flight to prove
      the stack answers the Step 2 smoke request set (12/12 green)
      before the suite starts.
   4. Seeds the expanded fixture pack via the Phase 3 seed extension
      (wipe-and-reseed on every invocation per **D-R**).
   5. Runs the Go suite:
      `cd tests/parity/suite && PARITY_PROFILE=legacy
      PARITY_AC_BASE_URL=http://localhost:${PARITY_AC_PORT:-28090} ...
      go test -tags integration -run ^TestParitySuite$ -count=1 -v ./...`.
      Every `PARITY_*` env var defaults to the Step-2 port map;
      overrides come from the shell.
   6. On success prints the line `Parity suite passed: 130/130 cases green.`
      (or the current leaf-sub-case count if the catalogue grows).
   7. On failure prints the list of golden mismatches (file pairs
      `golden/<x>.json` ↔ `golden/<x>.observed.json`) and exits non-
      zero.
   8. Does **not** tear the stack down automatically — teardown is a
      manual `docker compose down -v` step the developer runs after
      inspection, the same way Step 2's workflow is documented.
8. **Phase 7 — Run, record, re-run, document, close.** Phase 7 is the
   **done-gate** phase per **D-W** and is substantially larger than
   the earlier "Phase 7 — Documentation and handover close" framing.
   Sequence:
   1. On a clean checkout, run `run-parity-suite.sh` **in record mode**
      (`PARITY_GOLDEN_RECORD=1 PARITY_PROFILE=legacy bash ...`) once.
      Inspect each generated golden file by hand: confirm it contains
      the shape the parity contract describes for that endpoint and
      does not have obvious garbage (empty, truncated, or exception
      strings).
   2. Commit the goldens.
   3. Re-run `run-parity-suite.sh` **without** record mode. Confirm the
      final line `Parity suite passed: 130/130 cases green.` and
      confirm `git status` shows zero diff against the committed
      goldens. **This is the stability check**: if the second run
      diffs, the legacy server has non-determinism in its response
      and the ignore-list needs widening (escalate as OQ before
      committing any widening).
   4. Extend `tests/parity/README.md` with a new section describing:
      how to run the suite, the `PARITY_GOLDEN_RECORD=1` record mode,
      the exact location of the golden files, the matrix of covered
      scenarios per endpoint (direct copy of the Planned Test
      Catalogue below, updated with any scenario added during
      execution), and a pointer to Step 4 as the consumer of the
      captured goldens.
   5. Update this handover's `Done` checklist (every `[ ]` flipped to
      `[x]`), fill the `D-I` decision with the actual Go module path
      chosen in Phase 2, resolve or leave explicit the
      `Open Questions`, and mark Step 3 of the parent plan as done
      with links to the new Go module, the run script, the golden
      directory, and the extended seed fixtures.
   6. Fill the Execution Report section at the bottom of this file
      with: implemented changes (files written, line counts), wall-
      clock times (cold run and warm run of `run-parity-suite.sh`),
      golden file count, total Go test count observed by `go test
      -v`, remaining gaps (OQs still open, scenarios deferred to
      Step 4).
   File an ADR **only** if:
   - Phase 3 discovered a parity-contract row that genuinely cannot be
     reached without loading the CloudBSS bundle (escalation of
     **D-C**); or
   - Phase 4 discovered a legacy wire shape that diverges from the
     parity contract's documentation so much that the Go helper layer
     cannot reproduce it (escalation of **D1** / **D6** / **D-V**); or
   - Phase 5 needed to widen the golden ignore-list beyond
     `Obligations` and audit-trail metadata (escalation of **D1**);
   - Phase 7's stability check found non-determinism in a golden and
     the fix requires more than a field-ignore option (escalation of
     **D-W**).

### Minimum evidence bar

A decision recorded in this handover's `Decisions` section is only acceptable when
it has:

1. A concrete reference to a file in
   `sample-sources/access-control-spring-libs/access-control-client/`,
   `sample-sources/access-control/`, the parity contract, or the Step 2 handover
   that forced the decision.
2. An explicit rejected alternative with a one-line reason.
3. A clear binding to the test-suite artefacts (which Go test file,
   helper function, golden file, or seed fixture it affects).

If any of these three items is missing, move the decision to `Open Questions` and
stop until it is resolved.

### How to verify the deliverable

Before declaring the task done:

1. On a clean checkout, run `bash tests/parity/scripts/build-images.sh` and
   confirm both `authz-agent/parity-access-control:local` and
   `authz-agent/parity-identity-provider:local` are present.
2. Run `bash tests/parity/scripts/run-parity-suite.sh`. Confirm the stack reaches
   `healthy`, `smoke.sh` prints its 12/12 line, the suite runs to completion, and
   the final line is `Parity suite passed: 130/130 cases green.` (130 leaf
   sub-cases over the current 83-row catalogue; catalogue growth still requires
   both a handover edit and an explicit owner sign-off on the added rows).
3. Inspect the golden tree under
   `tests/parity/suite/testdata/golden/` and confirm it contains one file
   per golden-asserted **sub-case** per **D-X** (~120 files total — 80
   golden-asserted rows with some rows expanded into multiple sub-cases
   via `s.Run`; the 3 exception-asserted validation rows 11, 16, 29 have
   no golden). Each file is expected to be well under 10 KB of JSON —
   anything noticeably larger is a sign the fixture over-populated the
   response and should be trimmed to the minimum the scenario needs.
   Confirm that the diff from a freshly-committed state is zero after a
   second run without record mode (this is the **D-W** stability check).
4. Re-run with a deliberate mutation to the legacy policy bundle (for
   example, delete the `ROLE_PARITY_READER` role from the OLS allow
   fixture) and confirm the suite fails loudly with a `cmp.Diff` output
   that identifies the offending endpoint, fixture, and field path.
5. Run `PARITY_GOLDEN_RECORD=1 PARITY_PROFILE=legacy bash
   tests/parity/scripts/run-parity-suite.sh` and confirm that record
   mode overwrites goldens without failing the run. Then run with
   `PARITY_PROFILE=authz-agent PARITY_GOLDEN_RECORD=1` and confirm the
   suite **fails fast in `SetupSuite`** before any test executes — the
   record-mode guard from **D-F** must block accidental baseline
   capture against Authz Agent.
6. Tear the stack down with `docker compose down -v` and confirm no orphaned
   containers, volumes, or networks remain.
7. Re-read every table in this handover, the README update, and the seed fixture
   comments, confirming no empty lines between table rows and all links point at
   real files on disk.

Once all seven pass, write a short execution report at the bottom of this handover
— implemented changes (files written), validation performed (commands run, suite
observations, golden file count, wall-clock time), and remaining gaps
(`Open Questions`). Stop there. Do not move on to Step 4 of the parent plan in the
same session.

Build a deterministic integration-test suite under `tests/parity/suite/` that:

1. Exercises **all 10** in-parity endpoints from
   ../parity/access-control-client-api-surface.md
   against the legacy `access-control` reference stack brought up by Step 2.
2. Reads the wire protocol spec from
   `sample-sources/access-control-spring-libs/access-control-client/`
   (the Java thin client) as a **reference-only** documentation source
   per **D-V** — the Go suite reimplements every transport convention
   at the HTTP level faithfully, does not fork or subclass the thin
   client, and does not call it from a sidecar JVM.
3. Asserts parity on **deserialized response objects** per **D1**, with the
   `obligations` block excluded per **D3**.
4. Captures the deserialized legacy-baseline responses to golden JSON files that
   are committed to the repo, so Step 4 can re-point the same suite at Authz Agent
   by flipping one configuration value and diff against the exact same goldens
   without re-running the legacy stack.
5. Covers the scenario matrix the parity contract mandates: OLS allow/deny, RLS
   filter with `calculationResult` plus typed predicates, RLS predicate/condition,
   TOKEN / HEADER / GENERAL PIP-backed conditions, condition-language operator
   coverage (CLANG block), multi-row policy combining / OR-aggregation (AGG
   block), PIP-value template substitution into predicate strings (SUB block),
   entitlements PIP coverage against a mocked `entitlements-aggregator` (ENT
   block per **D-U**), at least one `Incoming-Token` non-anonymous fixture per
   implemented endpoint, at least one `Authorization-Type: anonymous` fixture
   per implemented endpoint, and server-side validation/error fixtures per
   endpoint group. Wildcard-role fast-path coverage is **not** part of the
   scenario matrix per **D-S** — legacy simplified-policy format has no
   role-level wildcard construct.
6. Runs from a single wrapper script that brings up the Step 2 stack, seeds
   the expanded fixture pack, runs `go test -tags integration` against the
   Go module at `tests/parity/suite/`, and reports deterministic results.
   Requires Go 1.22+ on the host, matching the existing
   `tests/integration/testify/` convention per **D-G**.

No code changes to Authz Agent (`image/`, Envoy, Rego, Go) are in scope. No
work on the Authz Agent parity run (Step 4) or on edits to
`docs/compatibility.md` is in scope.

### Inputs

Primary sources to read (all paths relative to the repository root):

- ../parity/access-control-client-api-surface.md
  — the parity contract. Defines the 10 endpoints, the transport conventions the
  suite must satisfy at the thin-client level (Incoming-Token, Authorization-Type,
  HeadersFilter, tenant_id / userId query params, `/api-version` gate), and the
  decisions D0–D8 that bound this step (especially **D1** deserialized-object
  parity, **D3** v2 obligations exclusion, **D4** unmodified thin-client JAR,
  **D5** GENERAL PIP in scope, **D6** ACMockServer not authoritative).
- ../plans/20260413-access-control-parity-testing-plan.md
  — parent plan, Step 3 row.
- 20260413-access-control-reference-stack-task.md
  — Step 2 handover. Defines the exact stack the suite runs against, the seeded
  smoke fixtures, the mock PIP control surface, the identity-provider realm layout
  (`parity` realm + `cloud-common` realm + `parity-m2m` client), the port map
  (`PARITY_AC_PORT=28090`, `PARITY_PIP_PORT=28091`, `PARITY_IDP_PORT=25557`), and
  and the port map / seed channel that the Go suite must honor.
- `sample-sources/access-control-spring-libs/access-control-client/` — the thin
  client. Read end-to-end, starting from:
  - `RemoteACCommon` (v1 and v2) — the concrete HTTP transport.
  - `AbstractAccessControl` — the user-facing API.
  - `SpringRemoteACCommon` / `M2MOAuth2ClientInterceptor` /
    `OAuth2ClientInterceptor` / `RelayRestTemplateConfiguration` — the header,
    Incoming-Token, and `/api-version` gating behavior.
  - `SpringApiVersionService` / `AbstractApiVersionService` — the
    `isApiAvailable` probe that every v2 call is gated on, and that the v1
    bootstrap uses to pick an interceptor.
  - The DTO model tree under
    `sample-sources/access-control-java-libs/access-control-policy-decision-point*/`
    — the DTOs the suite asserts against (`EvaluationResultImpl`,
    `OldFilterEvaluationResult`, `CheckResourceResponse`, `CheckResourcesResponse`,
    `FilterResponse`, `ApiVersionResponse`).
- `sample-sources/access-control/` — the legacy server. Cross-reference only;
  used to verify that a given policy fixture lands on the code path the test
  expects and to design validation-error fixtures.
- 20260413-access-control-reference-stack-task.md §Follow-ups
  — runtime knowledge accrued during the first Step 2 bring-up (the Gap 5 /
  Gap 7 history, the AC `command:` override, the `ac-token-fetcher` sidecar).
  The suite's Phase 3 seed extension must stay compatible with all of it.
- `tests/parity/compose/seed/policies/*.json` and
  `tests/parity/compose/seed/scripts/seed-access-control.sh` — the current
  seed surface the Phase 3 seed extension must grow, not replace.
- `tests/parity/compose/idp-seed/parity-realm.json` +
  `cloud-common-realm.json` — the realm(s) the suite must obtain tokens from.
  Any additional claims needed for TOKEN-PIP scenarios must be added here in a
  strictly additive way.
- `tests/integration/pipstub/main.go` — the mock PIP service binary; the
  `/__mock__/responses` control surface lives here, and the Phase 4 tests pin
  per-scenario responses through it. Per **D-U** the same binary is also
  used as the `entitlements-mock` service (separate container, same
  control surface).
- `sample-sources/access-control/documentation/development-guide/entitlements/README.md`
  — the legacy AST grammar for `subject.entitledResources.of(...).as(...)`,
  including the supported operators (CONTAINS / NOT CONTAINS / IN /
  NOT IN / CONTAINS ANY / NOT CONTAINS ANY / IS EMPTY / IS NOT EMPTY)
  and the single-quote escaping limitation. Required reading before
  Phase 3 writes the ENT block fixtures (rows 76–83).
- `sample-sources/access-control-java-libs/access-control-policy-decision-point/src/main/java/com/netcracker/security/authorization/abac/policy/entitlements/EntitlementsServiceImpl.java`
  — the legacy AC consumer that owns the four EA endpoint paths
  (V1 + V3 + per-definition lookup). The mock per **D-U** must satisfy
  exactly these path templates.
- `sample-sources/access-control-spring-libs/access-control-local-client/src/main/java/com/netcracker/security/authorization/abac/entitlements/EntitlementsPipServiceImpl.java`
  — the Spring REST client that legacy AC uses to talk to the
  aggregator. Read end-to-end to confirm the `Tenant` header
  convention, the V3 `apiVersionService.isApiAvailable` probe gate,
  the cache key (`SimpleKeyGenerator(userId, tenantId)`), and the
  `GetDirectUserEntitlementsResponse` request/response field set.
- `sample-sources/entitlements-aggregator/` — the real EA service.
  Cross-reference only; Phase 1 reads enough of it to verify the
  mock's wire shapes match the real EA, **not** to bring it up. Note
  the EA's bootstrap dependencies on Kafka and a dedicated Postgres
  database are explicitly out of scope for the parity stack per
  **D-U**.
- `sample-sources/entitlements-aggregator/documentation/development-guide/entitlement-definitions/README.md`
  — background on the Cypher-like entitlement-definition syntax. Not
  required by the ENT block (the mock returns pinned `entitlements[]`
  arrays directly without going through a definition resolver), but
  useful context for understanding what the real EA does on a
  definition cache miss.
- ../decisions/20260413-authz-agent-adr-0049-reintroduce-incoming-token-on-legacy-ingress.md
  — background only. This handover does not implement ADR-0049; it only needs
  to know that the fixtures' design (Incoming-Token relay, anonymous, v2 `/api`
  minor probe) must match what the ADR locks on the Authz Agent side so the
  same fixtures survive the Step 4 rerun.
- Existing compatibility material: ../compatibility.md,
  ../policy-format.md, ../source-analysis.md.
  Cross-reference only. Do not edit.

### Deliverables

1. A new **Go module** at `tests/parity/suite/` containing (per **D-A**,
   **D-B**, **D-I**):
   1. `go.mod` + `go.sum` declaring `github.com/stretchr/testify`,
      `github.com/google/go-cmp`, `github.com/golang-jwt/jwt/v5` as
      direct deps. **No** dependency on the Java thin-client JAR.
   2. `suite_test.go` — testify `ParitySuite` entry point with
      `TestParitySuite(t *testing.T) { suite.Run(t, new(ParitySuite)) }`.
      Build tag `//go:build integration` at the top of every test file.
   3. Test files under `tests/parity/suite/` using the per-row naming
      convention Phase 4 actually landed:
      - `test_row01_api_version_test.go`
      - `test_row02_check_resource_v1_test.go`
      - `test_row02_fixture_cases_test.go`
      - `test_row02_clang_additional_cases_test.go`
      - `test_row02_agg_additional_cases_test.go`
      - `test_row02_entitlement_cases_test.go`
      - `test_row03_*`, `test_row04_*`, ..., `test_row10_*`
      The CLANG / AGG / SUB / ENT slices are intentionally co-located with
      the row files that share their fixtures, rather than split into
      dedicated block-level filenames.
   4. Shared helpers at the module root:
      - `catalog.go` — `ParityEndpointId` constants (one per parity-
        contract row), the row metadata table, and the
        endpoint→struct-factory lookup used by `GoldenComparator`.
      - `helpers.go` — Keycloak token acquisition (adapted from
        `tests/integration/testify/helpers.go` per **D-I**), HTTP
        client setup, the transport-convention HTTP helper functions
        (one per parity-contract row; they enforce every **D-V** item
        at the wire level).
      - `compare.go` — `GoldenComparator` (per **D-M**) using
        `encoding/json` + `go-cmp`.
      - `record.go` — record-mode writer gated by `PARITY_GOLDEN_RECORD=1`
        - `PARITY_PROFILE=legacy` per **D-F**.
      - `pip_control.go` — control-surface client that pins / resets
        `pip-mock` and `entitlements-mock` responses per **D-O** +
        **D-U**. Exposes `PinPip(path, body)`, `PinEntitlements(path,
        body)`, `ResetAll()`.
      - `tokens.go` — `TokenFactory` with `M2MToken()` and
        `EndUserToken(UserProfile)` where `UserProfile` is a Go
        `type UserProfile int` enum mapped to the seeded users per
        **D-N** (`PARITY_READER`, `PARITY_REVIEWER`,
        `PARITY_MULTI_ROLE`, `PARITY_OTHER`, `PARITY_ANON_BASELINE`).
   5. Go struct model at `tests/parity/suite/model/` — one file per
      legacy DTO, each with a package-level comment citing the legacy
      Java source class. Files: `api_version.go`, `check_resource.go`,
      `check_resources.go`, `filter.go`, `entitlements.go`. Struct
      JSON tags match the Jackson field names verbatim.
   6. **`GoldenComparator` contract (per D-M).** Reads each golden
      JSON file via `encoding/json.Unmarshal` into the concrete Go
      struct for the parity-contract row under test, unmarshals the
      fresh response the same way, and compares the two typed
      structs with `cmp.Diff(expected, actual, cmpopts...)`. On
      mismatch, fails the test via `s.T().Errorf` with the diff as
      the message and writes `<golden>.observed.json` next to the
      golden for manual inspection. Endpoint-to-Go-struct mapping
      (per **D-M** lookup table, duplicated here for easy reference):

      | Parity row | Go struct                                                        |
      | ---------- | ---------------------------------------------------------------- |
      | 1          | `model.ApiVersionResponse`                                       |
      | 2          | `bool`                                                           |
      | 3          | `[]string` (sort-insensitive compare)                            |
      | 4          | `map[string][]string` (sort-insensitive compare)                 |
      | 5          | same as row 4                                                    |
      | 6          | `model.OldFilterEvaluationResult`                                |
      | 7          | `model.CheckResourceResponse` (Obligations ignored via cmpopts)  |
      | 8          | `model.CheckResourcesResponse` (Obligations ignored via cmpopts) |
      | 9          | same as row 8                                                    |
      | 10         | `model.FilterResponse` (Obligations ignored via cmpopts)         |

      Every test passes its `ParityEndpointId` constant to the
      comparator, not a Go type directly — the mapping is the single
      place where struct-endpoint binding is defined, and an unknown
      id `panic`s on lookup. CLANG / AGG / SUB / ENT rows inherit
      the struct from the parity-contract row they cite
      (`check/resource` → `bool`, `check/filter` →
      `model.OldFilterEvaluationResult`, etc.).

   7. `tests/parity/suite/testdata/golden/<endpoint>/<row>/<sub-case>.json`
      (per **D-X** sub-case granularity) for multi-sub-case rows, or
      `tests/parity/suite/testdata/golden/<endpoint>/<fixture>.json`
      for single-case rows — committed baseline responses captured in
      record mode against the legacy stack. Total expected file count
      is ~120, confirmed in the Phase 7 Execution Report (exact count
      depends on how many sub-cases each row ends up with once
      Phase 1 resolves legacy operator spellings for CLANG rows).
   8. Env-var driven config via `os.Getenv` with defaults. No
      `application-parity.yaml` / Maven profile files — the Go suite
      reads everything from `PARITY_*` env vars. The Step 4 handover
      re-points by setting `PARITY_AC_BASE_URL` and `PARITY_PROFILE=authz-agent`.
2. An expanded seed fixture pack under `tests/parity/compose/seed/policies/`
   (or a sibling `suite/` subdirectory, whichever keeps diffs against Step 2
   clean), with one policy/PIP JSON file per scenario class from the
   Planned Test Catalogue below. Each file must carry an inline `_comment`
   linking it back to the parity-contract row and scenario ID it proves.
3. An extended seed loader script under `tests/parity/compose/seed/scripts/`
   (new file, not an edit of the Step 2 `seed-access-control.sh` unless the
   executor can guarantee the Step 2 smoke fixture load order is preserved)
   that PUTs the expanded fixture pack after the Step 2 smoke fixtures have
   loaded. The ordering constraint from Step 2 — PIPs before policies so
   `condition` validation does not reject the batch — must be preserved.
4. A runner script `tests/parity/scripts/run-parity-suite.sh` (new) that
   orchestrates the Phase 6 flow above. Bash + `docker compose` + `go test`
   — no Maven, no Java. Assumes Go 1.22+ on the host (matching the
   existing `tests/integration/testify/` convention).
5. A README update at `tests/parity/README.md` covering: how to run the
   suite, how to record goldens on a new baseline, the matrix of covered
   scenarios (copy of the Planned Test Catalogue), the location of the
   goldens, known non-parity gaps, and a pointer to Step 4 as the consumer
   of the captured goldens.
6. An update to
   20260413-access-control-parity-testing-plan.md:
   mark Step 3 as done, add a row to the Handovers table pointing at this
   file plus the new Go module / run script / golden directory, and
   note the validation status (130/130 leaf sub-cases green on a clean bring-up,
   confirmed twice in a row per **D-W** stability check).
7. Updates to this handover with the final `Done` checklist, filled
   `Decisions` section, and a short execution report (implemented changes,
   validation performed, remaining gaps).
8. File an ADR **only** if Phase 3 forces an escalation of **D-C** (must
   load the CloudBSS bundle to cover a parity-contract row), Phase 4
   forces an escalation of **D1** / **D6** / **D-V** (a legacy wire
   behavior diverges from the parity-contract documentation and cannot
   be replicated by the Go helper layer), Phase 5 must widen the golden
   ignore-list beyond `Obligations` and deterministic audit metadata,
   or Phase 7's stability check finds non-determinism that cannot be
   fixed with an `IgnoreFields` option (escalation of **D-W**).

### Method

1. Read everything in Inputs in order. Start from the parity contract's
   Summary Table so the test-class-to-endpoint mapping stays mechanical.
2. For every row in the Summary Table, identify:
   - The concrete thin-client method to call (column "Client callsite" of the
     parity contract).
   - The DTO shape to assert on (column "Request DTO" + "Response DTO").
   - The minimum policy/PIP fixture set to seed so the call produces a
     non-trivial response in both the allow branch and the deny branch.
   - Which of the four auth variants the row needs (`Incoming-Token`
     non-anonymous, `Authorization-Type: anonymous`, M2M-only for
     `/api-version`, and any variant where the M2M token identity diverges
     from the Incoming-Token identity so the two are observably distinct).
3. Build the Phase 3 fixture pack from the ground up, not by patching Step 2's
   smoke fixtures. Leave the Step 2 smoke fixtures alone so `smoke.sh` stays
   green. Cross-link every fixture to the parity-contract row and scenario ID
   it proves.
4. Bootstrap the Go module (Phase 2) **before** writing the first test so
   `go build ./...` and `go test -tags integration -run ^$ ./...` both
   exit 0 on an empty module. Only
   then add test classes one parity-contract row at a time.
5. Run the suite in record mode against the legacy stack once the full test
   catalogue compiles. Inspect the generated goldens one file at a time
   before committing them — a golden that looks too small or too uniform is
   a sign the fixture did not actually land on the expected policy.
6. Re-run the suite a second time without record mode. The second run is the
   one that proves the goldens are stable; commit them only after the second
   run is green.
7. Implement `GoldenComparator` with `cmp.Diff` + `cmpopts`, ignoring
   only `Obligations` (per **D3** / **D-E**) and any fields listed in
   the minimum ignore-list documented in the README. Every additional
   ignored field must have a one-line justification comment in
   `compare.go` next to the `cmpopts.IgnoreFields` call.
8. Wire the runner script last, after `go test -tags integration
   ./...` is stable locally against the legacy stack.
9. Walk the `How to verify the deliverable` checklist and fill the execution
   report.

### Constraints

1. **English only** for every file under `docs/ai/`, every Go source
   comment, and every README addition.
2. **No edits to `docs/compatibility.md`.** Any compatibility
   implication must be recorded as an Open Question and handed off to
   the `compatibility.md` follow-up handover (D8 of the parity
   contract).
3. **No production code changes.** Do not edit `image/`,
   `sample-sources/`, `tests/svt/`, `tests/integration/pipstub/`,
   `tests/integration/runtime/`, `tests/integration/testify/`,
   `tests/integration/upstream-capture/`, `tests/unit/`, or `.cursor/`.
   New files under `tests/parity/suite/`, `tests/parity/compose/seed/`,
   and `tests/parity/scripts/` are in scope. Copying helper code from
   `tests/integration/testify/helpers.go` into
   `tests/parity/suite/helpers.go` is allowed per **D-I** with a
   comment citing the source.
4. **No shadow of the thin client.** Per **D4** of the parity contract
   (as reinterpreted by **D-V**). Go tests replicate the wire protocol
   documented in the parity contract; they must not invent transport
   behaviors the thin client does not speak. If a test case seems to
   need a wire behavior not in the transport-convention inventory,
   open an Open Question and stop.
5. **No `build:` directives** in any Compose file (per **D-B** of
   Step 2). The Phase 6 runner script must use the Phase 3 build
   scripts of Step 2.
6. **No new services in `tests/parity/compose/docker-compose.yml`**
   beyond those justified by a locked decision. Iteration 6 **D-U**
   adds `entitlements-mock`; any other new service requires another
   decision with rejected alternatives. The parity stack from Step 2
   already includes `access-control`, `identity-provider`, `postgres`,
   `pip-mock`, `ac-token-fetcher`, and `ac-seed`.
7. **Goldens are committed.** Do not `.gitignore` them. The whole
   point is that Step 4 re-asserts against the same file tree. Per
   **D-W** the task is not done until the goldens are in the repo and
   stable under a second run.
8. **Record mode is guarded.** Record mode must fail loudly if
   invoked with any `PARITY_PROFILE` other than `legacy` so the
   Authz Agent rerun in Step 4 cannot silently mutate the baseline.
9. **Deterministic order.** Tests must not call `t.Parallel()` in any
   parity test function — the `pip-mock` / `entitlements-mock`
   control surfaces are shared singletons and concurrent `SetupTest`
   pins would race. Each test pins its mock state explicitly in its
   own `SetupTest`; `TearDownTest` resets both mocks.
10. **Markdown validation.** Tables in this handover, the README
    update, the Planned Test Catalogue below, and any new doc must
    have no empty lines between rows, and Mermaid diagrams must use
    valid syntax.
11. **No edits to `tests/parity/compose/docker-compose.yml`
    healthchecks or existing services.** Iteration 6 **D-U** adds
    `entitlements-mock` as a new service and two env vars on
    `access-control`; no other compose changes are permitted.
    The Step 2 bring-up is delicate (Gap 5 SPI chain, Gap 7 realm
    fix); any further compose-level change must go through an Open
    Question first.
12. **Golden field stability.** If a field is non-deterministic on
    the legacy side (e.g. audit-trail timestamps, request ids), the
    suite must either not assert on it or compare it for **presence
    and type** only, never for exact value. Each such field must be
    enumerated in the README and in `compare.go`'s `cmpopts` list.
13. **Go module hygiene.** Do not import from
    `tests/integration/testify/` — it is a test binary package, not
    an importable library. Copy helpers with attribution per **D-I**.
    Do not add external HTTP client libraries (`resty`, `go-retryablehttp`)
    — stdlib `net/http` + the copied helpers are sufficient.

## Execution Prompt

<!-- folded from 20260414-access-control-parity-test-suite-task.prompt.md by migrate_handovers_layout (security-ADR-0023) -->

### Prompt: Access Control Parity Integration-Test Suite (Legacy Baseline)

#### Context

You are executing a task in the Authz Agent repository. The task is defined in
[20260414-access-control-parity-test-suite-task.md](20260414-access-control-parity-test-suite-task.md).
That handover is the single source of truth for **what** to do — Goal, Inputs,
Deliverables, Method, Done checklist, the pre-locked Decisions section (D-A
through D-Z; only D-I is still open to the executor and must be filled during
Phase 2 with the Go module path), and the Planned Test Catalogue (83 rows,
~120 expected golden files after **D-X** per-sub-case splitting, grouped per
parity-contract row plus dedicated CLANG, AGG, SUB, and ENT blocks, covering
OLS / RLS / TOKEN-PIP / HEADER-PIP / GENERAL-PIP / entitlements /
Incoming-Token / anonymous / validation). Read it in full before starting.
This prompt file only adds the generic repository rules and constraints that
apply to the execution.

**IMPORTANT — iteration-7 Go pivot (still in force after iteration 8).**
The suite is **Go + testify**, not Java + JUnit. **D-A was completely
rewritten in iteration 7** by the parent plan owner: the suite is a Go
module under `tests/parity/suite/` using `github.com/stretchr/testify/suite`
and `github.com/google/go-cmp/cmp` (the latter confirmed in iteration 8
as an acceptable new dependency), following the existing
`tests/integration/testify/` pattern. The parity contract's **D4** was
**rewritten in iteration 8** (not just overridden locally) to say "capture
the API behavior the client uses, language-agnostic" — see
../parity/access-control-client-api-surface.md §Decisions D4
for the rewritten text. D-V of this handover is the operational
implementation of the rewritten D4. Earlier iterations of this prompt
referenced Java / JUnit 5 / AssertJ / Maven — all of those are obsolete.
Phase 1 reads the thin client source as a **reference-only documentation
source** and produces a Transport Convention Inventory that the Go HTTP
helper layer implements.

**Iteration 8 additions:** **D-X** (per-sub-case golden files via testify
`s.Run` subtests — golden file count grows from ~80 to ~120, but row
count stays 83), **D-Y** (≤15 minutes warm-run wall-clock budget for
`run-parity-suite.sh`; cold runs unbounded), **D-Z** (CI integration is
out of scope — `run-parity-suite.sh` is local-only, no GitHub Actions /
GitLab CI wiring).

This task is an **integration-test authoring task**: you are producing a new
**Go module** under `tests/parity/suite/` (`go.mod` + test files), an
expanded seed fixture pack under `tests/parity/compose/seed/policies/`, a
suite runner script under `tests/parity/scripts/`, golden baseline JSON
files under `tests/parity/suite/testdata/golden/`, and a README update. You
are **not** modifying Authz Agent production code (Envoy, Lua, Rego, Go).
You are **not** re-pointing the suite at Authz Agent — that is Step 4 of the
parent plan and will be a separate handover.

**Per D-W, task done = all 83 tests green + all goldens committed + a
second run produces zero diff.** Drafting the handover is not the
deliverable; running the suite to green-and-stable is.

#### Pre-read (mandatory)

Read these in order before doing anything else:

1. AGENTS.md — repository goal, agent rules, ADR and
   handover formats, documentation map.
2. docs/conventions.md — documentation and validation
   conventions.
3. docs/architecture.md — Authz Agent target
   architecture. Background only; this step does not modify Authz Agent itself.
4. docs/compatibility.md — current compatibility
   baseline. Cross-reference only; this step does not edit it.
5. docs/policy-format.md — simplified policy/PIP
   compatibility rules. Essential for the Phase 3 seed extension (the fixtures
   are written in the same simplified format Step 2 already uses).
6. docs/source-analysis.md — background. Not
   authoritative on its own.
7. docs/plans/20260413-access-control-parity-testing-plan.md
   — parent plan. Pay particular attention to the Step 3 row, the Out of
   Scope section, and the Validation section.
8. docs/parity/access-control-client-api-surface.md
   — the parity contract. **This is the authoritative source of truth for the
   10 endpoints the suite must exercise**, the transport conventions the tests
   must satisfy at the thin-client level, and the decisions D0–D8 that bound
   this step (especially **D1** deserialized-object parity, **D3** v2
   obligations exclusion, **D4** unmodified thin-client JAR, **D5** GENERAL
   PIP in scope, **D6** ACMockServer not authoritative). Read end-to-end.
9. docs/handovers/20260413-access-control-reference-stack-task.md
   — Step 2 handover. This is the stack the suite runs against. Pay
   particular attention to the Follow-ups section — Gap 5 (SPI chain fixes)
   and Gap 7 (`cloud-common` `parity-m2m` client) must stay closed after
   the Phase 3 seed extension lands, and `smoke.sh` must keep printing
   `Smoke run passed: 12/12 checks green.`.
10. docs/decisions/20260413-authz-agent-adr-0049-reintroduce-incoming-token-on-legacy-ingress.md
    — background only. This step does not implement ADR-0049; it only needs
    to know that the fixtures must be designed so that Step 4 can re-run the
    same suite against Authz Agent without edits (Incoming-Token relay path,
    `/api-version` gate, v2 synthetic-deny short-circuit).
11. [20260414-access-control-parity-test-suite-task.md](20260414-access-control-parity-test-suite-task.md)
    — **the task itself**. Read it after the generic material above. Pay
    particular attention to the Decisions section (D-A through D-H are
    pre-locked; D-I must be filled during execution) and to the
    [Planned Test Catalogue](20260414-access-control-parity-test-suite-task.md#planned-test-catalogue)
    table which enumerates the 83 test cases that must be implemented
    (rows 1–48 cover the parity-contract endpoint matrix; rows 49–60 are
    the CLANG block covering the simplified-policy condition-language
    surface; rows 61–67 are the AGG block covering multi-row policy
    combining / predicate OR-aggregation per ADR-0025; rows 68–75 are
    the SUB block covering predicate-template substitution — including
    GENERAL PIPs that return scalar/leaf values; rows 76–83 are the
    ENT block covering `subject.entitledResources.of(...).as(...)` AST
    against a mocked `entitlements-aggregator` per **D-U**).
    Wildcard-role rows are absent from the catalogue per D-S: Phase 1
    reading confirmed that legacy `access-control` simplified-policy
    format has no role-level wildcard construct, so there is no legacy
    counterpart to test against. The entitlements-aggregator service
    itself is **not** brought up — only an `entitlements-mock` HTTP
    service (same `pip-stub:local` binary as `pip-mock`, separate
    compose service) that implements the four EA endpoints
    `GET /api-version`, `POST /api/v1/entitlements-aggregator/entitlements`,
    `GET /api/v3/user-entitlements/user/{userId}`, and
    `GET /api/v3/user-entitlements/user/{userId}/resource-type/{rt}/name/{name}`.
12. `sample-sources/access-control-spring-libs/access-control-client/`
    — the thin-client source (**reference only** per iteration-7 D-V;
    the Go suite reimplements the wire protocol rather than calling
    the JAR). Start from `pom.xml`, then trace:
    `RemoteACCommon` (v1 + v2), `AbstractAccessControl`, `SpringRemoteACCommon`,
    `M2MOAuth2ClientInterceptor`, `OAuth2ClientInterceptor`,
    `RelayRestTemplateConfiguration`, `SpringApiVersionService`,
    `AbstractApiVersionService`. The suite imports and drives these classes;
    understanding their interaction is Phase 1 of the handover.
13. DTOs under
    `sample-sources/access-control-java-libs/access-control-policy-decision-point*/`
    — `EvaluationResultImpl`, `OldFilterEvaluationResult`,
    `CheckResourceResponse`, `CheckResourcesResponse`, `FilterResponse`,
    `ApiVersionResponse`, `ApiVersionSpecification`, `CheckAccessRequest`,
    `CheckResourcesRequest`, `CheckResourcesRequestEntry`, `Flags`. These
    are the types the tests assert against after deserialization.
14. `tests/parity/compose/seed/policies/*.json` and
    `tests/parity/compose/seed/scripts/seed-access-control.sh` — the
    existing seed surface the Phase 3 extension must grow, not replace.
15. `tests/parity/compose/idp-seed/parity-realm.json` +
    `cloud-common-realm.json` — realms the suite obtains tokens from.
    Phase 3 extends them additively if a TOKEN-PIP or end-user password
    grant scenario requires it.
16. `tests/integration/pipstub/main.go` — mock PIP service, including the
    `POST /__mock__/responses` control surface that the Phase 4 tests pin
    per-scenario responses through.

Do not start the implementation until all sixteen files (and directories)
have been read.

#### Repository rules (must follow)

1. **Read before write.** Before writing any Go source, `go.mod`, fixture
   JSON, or bash script, load `docs/architecture.md`,
   `docs/compatibility.md`, `docs/policy-format.md`, and
   `docs/conventions.md` into your working context.
2. **Load related ADRs.** Search `docs/decisions/` for any ADR whose
   subject overlaps with the legacy `access-control` API surface, the
   simplified policy/PIP format, PIP handling (TOKEN / HEADER / GENERAL),
   the canonical `authorize` contract, or the Envoy legacy transforms.
   Link the relevant ones from this handover's `Decisions` section if they
   affect a test-design choice. ADR-0049 is specifically pre-read above.
3. **Compatibility first.** Nothing produced by this task should recommend
   or require a change to the currently implemented canonical routes, the
   simplified policy/PIP format, or the Authz Agent SVT compose. The parity
   suite must coexist with SVT and with `tests/integration/runtime/` on a
   developer laptop.
4. **OPA boundary.** Do not change OPA internals. This step does not touch
   OPA at all.
5. **No production code changes.** Do not edit `image/`, `sample-sources/`,
   `tests/svt/`, `tests/integration/pipstub/`, `tests/integration/runtime/`,
   `tests/integration/testify/`, `tests/integration/upstream-capture/`,
   `tests/unit/`, or `.cursor/`. New files under `tests/parity/suite/`,
   `tests/parity/compose/seed/`, `tests/parity/scripts/`, and extensions to
   `tests/parity/README.md` are in scope.
6. **No fork of the thin client.** Per **D4** of the parity contract. If a
   test case seems to require a thin-client change, open an Open Question
   and stop. The suite uses the unmodified
   `sample-sources/access-control-spring-libs/access-control-client/` JAR.
7. **No edits to `docs/compatibility.md`.** If Phase 4 surfaces a
   conflict with the current compatibility document, record it as an Open
   Question and hand it off to the `compatibility.md` follow-up handover
   (D8 of the parity contract). Do not silently edit `compatibility.md`.
8. **Sample sources are read-only.** Do not modify anything under
   `sample-sources/`. Per **D-C** of this handover, Step 3 does not load
   the CloudBSS bundle at all —
   `sample-sources/simplified-policy-sample/` stays a schema reference.
9. **Step 2 stack is protected.** The Phase 3 seed extension must leave
   `tests/parity/compose/docker-compose.yml` healthchecks and services
   unchanged, and must leave the existing smoke fixtures
   (`ols-allow.json`, `ols-deny.json`, `rls-filter.json`, `general-pip.json`,
   `general-pip-pips.json`) intact. `tests/parity/scripts/smoke.sh` must
   keep printing `Smoke run passed: 12/12 checks green.` after the Phase 3
   changes land. Run `smoke.sh` once before and once after the extension
   to verify.
10. **Step 2 follow-ups stay closed.** Gap 5 (SPI chain fixes) and Gap 7
    (`cloud-common` realm `parity-m2m` client) must remain closed; the
    Phase 3 seed extension must not reintroduce `client_not_found` or
    `invalid_client` errors in the access-control log.
11. **English only** for everything under `docs/ai/`, every Go source
    comment, every fixture `_comment` field, and every
    README addition.
12. **Markdown validation.** Tables in the handover, the README, the
    Planned Test Catalogue, and any new doc must have no empty lines
    between rows. Any Mermaid diagrams must use valid syntax.
13. **Delivery format.** Produce a brief execution report at the bottom of
    the handover (implemented changes, validation performed, remaining
    gaps). Do not prepare PR/MR output unless explicitly asked.
14. **Do not rely on memory.** Memories about the legacy stack, the thin
    client, or the parity-contract decisions may be stale. Verify every
    claim against `sample-sources/access-control-spring-libs/`,
    `sample-sources/access-control-java-libs/`, the parity contract, and
    Step 2 artefacts at the time of the work.
15. **Goldens are committed.** Do not `.gitignore` them. They are the
    single source of truth that Step 4 re-asserts against.
16. **Record mode is profile-guarded.** `PARITY_GOLDEN_RECORD=1` must
    only take effect when `PARITY_PROFILE=legacy` is set at the same
    time. Any other profile must fail loudly in `SetupSuite` before
    any test executes. This is a hard safety rail for Step 4.
17. **Determinism.** Every test must seed the mock PIP and any other
    mutable fixture in its own `SetupTest`. No `t.Parallel()` calls,
    no reliance on fixture state leaking across cases.

#### Method discipline

Follow the Phased Execution section in the handover as the procedure. In
addition:

- Work one phase at a time. Finish the full evidence trail and artefact for
  a phase before starting the next. Update the `Done` checklist after each
  phase, not in one batch at the end.
- Phase 1 (transport convention inventory + legacy engine reading)
  runs before Phase 2 (Go module bootstrap). The inventory must
  document every wire convention the Go helper layer will implement,
  grouped per parity-contract row, each with a file:line citation.
  Do not start writing Go test files until the inventory is complete.
- Phase 2 (Go module bootstrap) must produce a buildable empty module
  before Phase 3 or Phase 4 start. Verify the build in
  `maven:3.9-eclipse-temurin-21` via
  `tests/parity/scripts/run-parity-suite.sh` (or an ad-hoc
  `docker run` command that mirrors it) and confirm exit code 0 with zero
  test classes before adding the first fixture.
- Phase 3 (seed extension) adds fixtures **additively** under
  `tests/parity/compose/seed/policies/` (or a sibling `suite/`
  subdirectory). The Step 2 smoke fixtures are left in place. Run
  `smoke.sh` before and after to confirm the 12/12 line.
- Phase 4 (test catalogue implementation) works one parity-contract row at
  a time. For each row:
  - Implement the test class against the thin client.
  - Run it against the legacy stack in record mode.
  - Inspect the generated golden by hand; confirm it matches the
    parity-contract description of the response shape for that row.
  - Commit the golden only after a second run (without record mode) proves
    it is stable.
  - Only then move to the next parity-contract row.
- Phase 5 (`GoldenComparator` + record-mode guard) must be implemented
  before the first golden is committed. The comparator's ignore-list must
  be defended in code with a one-line justification per entry
  (`obligations` is the only pre-locked entry; everything else needs
  evidence).
- Phase 6 (runner script) is written last, after `go test -tags
  integration ./...` is stable
  locally. The script delegates to `tests/parity/scripts/build-images.sh`
  and to `tests/parity/scripts/smoke.sh` — it does **not** duplicate their
  logic.
- Phase 7 (documentation) updates `tests/parity/README.md` and the parent
  plan. The README must include the full Planned Test Catalogue table
  (copied from the handover, updated with any scenarios added during
  execution). Mark Step 3 of the parent plan as done and link this handover,
  the new Go module, the run script, and the golden directory from the
  Handovers row.

#### Delivery checklist

Before declaring the task done, verify:

1. `tests/parity/suite/go.mod` exists and the chosen module path is
   recorded in **D-I**; `go build -tags integration ./...` exits 0 on
   a clean checkout.
2. `tests/parity/suite/` contains the per-row Go test files that Phase 4
   actually landed: the root row files (`test_row01_api_version_test.go`,
   `test_row02_check_resource_v1_test.go`, ..., `test_row10_check_filter_v2_test.go`)
   plus row-suffixed fixture slices such as
   `test_row02_clang_additional_cases_test.go`,
   `test_row02_agg_additional_cases_test.go`,
   `test_row02_entitlement_cases_test.go`,
   `test_row06_sub_cases_test.go`, etc. The key invariant is one
   individually named leaf test per golden-asserted sub-case, not a
   particular filename taxonomy.
3. `tests/parity/suite/` root contains `suite_test.go`, `catalog.go`,
   `helpers.go`, `compare.go`, `record.go`, `pip_control.go`,
   `tokens.go`, plus `model/` with one Go struct file per legacy DTO.
4. Every scenario from [Planned Test Catalogue](20260414-access-control-parity-test-suite-task.md#planned-test-catalogue)
   is implemented and passes against the legacy stack. The final
   scenario count is written into the parent plan update as
   `130/130 cases green.` (130 leaf sub-cases over the current 83-row catalogue).
5. The Go suite reads its configuration from `PARITY_*` environment
   variables (no YAML / profile files); Step 4 re-points by flipping
   `PARITY_AC_BASE_URL` and `PARITY_PROFILE=authz-agent` alone.
6. `tests/parity/suite/testdata/golden/` contains one file per
   golden-asserted leaf case (`127` files in the final Step 3 run); the tree is smaller than
   ~800 KB total.
7. `tests/parity/compose/seed/policies/` (or a sibling `suite/` dir)
   contains the expanded fixture pack, each file with an inline
   `_comment` linking back to the parity-contract row and scenario
   ID it proves.
8. `tests/parity/scripts/run-parity-suite.sh` runs the full bring-up
   → smoke → seed → `go test` → report pipeline and exits cleanly on
   success. The final line is `Parity suite passed: 130/130 cases green.`.
9. `tests/parity/scripts/smoke.sh` still prints
   `Smoke run passed: 12/12 checks green.` after the Phase 3 seed
   extension AND after the **D-U** compose addition.
10. `tests/parity/README.md` is extended with a new section describing
    how to run the suite, the `PARITY_GOLDEN_RECORD=1 PARITY_PROFILE=legacy`
    record mode, the golden directory at
    `tests/parity/suite/testdata/golden/`, the covered-scenarios
    matrix, known non-parity gaps, and a pointer to Step 4 as the
    consumer of the captured goldens.
11. Every table in this handover, the README, and any new doc has no
    empty lines between rows.
12. The handover's `Done` checklist is fully updated (every `[ ]`
    flipped to `[x]`); **D-I** is filled with the chosen Go module
    path; remaining `Open Questions` are either resolved or left
    explicit with an owner (write `None` only if truly empty after
    execution).
13. **D-W stability check passed**: a second run of
    `run-parity-suite.sh` without record mode produces the same
    `Parity suite passed: 130/130 cases green.` line AND `git status`
    shows zero diff against the committed golden tree.
14. The parent plan
    20260413-access-control-parity-testing-plan.md
    has Step 3 marked as done and the new Go module, run script,
    golden directory, and seed fixture pack linked from the Handovers
    row.
15. If an ADR was filed (escalation of **D-C** / **D1** / **D6** /
    **D-V** / **D-W**), it is linked from both this handover's
    `Decisions` section and from the parent plan.
16. The execution report at the end of the handover lists:
    implemented changes (files written with line counts), validation
    performed (commands run, suite observations, golden file count,
    wall-clock time for cold and warm runs), total `go test -v` test
    count (may be larger than 83 if sub-cases use `t.Run`), and
    remaining gaps (`Open Questions`).

#### Out-of-scope reminders

- Do not re-point the suite at Authz Agent in this step — that is Step 4
  of the parent plan and will get its own handover. In particular, do not
  implement ADR-0049 on the Envoy / Lua / OPA side, do not touch
  `image/deployments/envoy/`, and do not add `incoming-token` to any Rego
  prohibited-headers list in this task.
- Do not benchmark or load-test the suite. Non-functional parity is tracked
  by the separate load-testing plan and is explicitly out of scope here
  (see parent plan Out of Scope item 3).
- Do not load the CloudBSS bundle from
  `sample-sources/simplified-policy-sample/` into the legacy stack. Per
  **D-C** of this handover the suite is driven by bespoke fixtures only.
- Do not modify `sample-sources/` in any way.
- Do not edit `tests/integration/pipstub/` or `tests/integration/runtime/`.
  The pip-stub already accepts the legacy GENERAL PIP call shape as a
  superset per Phase 5 of the Step 2 handover; if the Phase 4 GENERAL-PIP
  tests need a control-surface mutation the stub does not already support,
  raise an Open Question rather than editing the stub.
- Do not fork the thin client, do not subclass `RemoteACCommon` to skip
  `/api-version`, and do not drive endpoints via raw `RestTemplate`. Per
  **D4** of the parity contract.
- Do not put `build:` directives in any Compose file. Per **D-B** of Step 2.
- Do not remove or rename any Step 2 artefact. The Phase 3 seed extension
  is purely additive.
- Do not edit the parity Compose file's healthchecks or service layout.
  Gap 5 / Gap 7 history is the reason.

## Done

Per **D-W**, the task is done **only** when every item below is checked
AND the `run-parity-suite.sh` `Parity suite passed: 130/130 cases green.`
line (130 leaf sub-cases over the 83-row catalogue) has been observed
**twice in a row** on a clean checkout with the recorded goldens in place.

- [x] Phase 0 — Pre-read list complete (parity contract, parent plan,
  Step 2 handover bullet list, Transport Conventions section of the
  parity contract, thin-client source tree for wire-protocol
  reference, `tests/integration/testify/` for the Go testify pattern,
  `tests/integration/pipstub/` for the real control surface shape).
  Completed 2026-04-14 in session `task-20260414-access-control-parity-test-suite`.
- [x] Phase 1 — Transport Convention Inventory table under
  [Transport Convention Inventory](#transport-convention-inventory)
  below is fully populated, with every row citing a concrete legacy
  source file:line and naming the Go helper function it maps to. Every
  **D-V** item (1–14) has a row in the check table; no new items
  surfaced during Phase 1 reading. Two new Open Questions raised
  (OQ-SUITE-10 pipstub control surface correction, OQ-SUITE-11
  pipstub literal-path vs D-U templated EA routes), both resolved
  in-place for Phase 2.
- [x] Phase 2 — Go module at `tests/parity/suite/` compiles:
  `go build -tags integration ./...` exits 0, `go vet -tags integration
  ./...` exits 0, and `go test -tags integration -run ^$ ./...` exits 0
  (no matching tests, skeleton module compiles). **D-I** is filled with
  the chosen Go module path `authz-agent/tests/parity/suite` (matches
  the `authz-agent/tests/integration/testify` naming convention).
- [x] Phase 3 — Expanded seed fixture pack committed under
  `tests/parity/compose/seed/policies/` (or a sibling `suite/` dir);
  every fixture links back to its parity-contract row via inline
  `_comment`; the existing Step 2 `smoke.sh` still prints
  `Smoke run passed: 12/12 checks green.` after the seed extension AND
  after the **D-U** compose addition (run `smoke.sh` twice — once
  before, once after — and record both observations in the Execution
  Report); the new `entitlements-mock` compose service is reachable
  from `access-control` at `http://entitlements-mock:8080`.
  - [x] **Infrastructure slice (2026-04-14):** `parity-realm.json`
    extended with `parity-end-user` password-grant client + 4 test
    users + `department`/`tier` claim mappers + 2 roles;
    `docker-compose.yml` extended with the `entitlements-mock`
    service + AC env vars; both `smoke.sh` runs (before the edits
    and after full stack rebuild) printed
    `Smoke run passed: 12/12 checks green.`; end-user tokens mint
    with expected claims on all 4 new users; `entitlements-mock`
    reachable from AC at `http://entitlements-mock:8080`. See
    [§Phase 3 — Infrastructure slice (2026-04-14)](#phase-3--infrastructure-slice-2026-04-14).
  - [x] **Fixture-pack slice (2026-04-14 continuation):** expanded
    policy/PIP fixtures under `seed/policies/suite/` and the
    `seed-access-control.sh` extension are now live. Clean-stack
    validation after the leaf-alias fix prints `parity-ac-seed`
    `exited:0`, `smoke.sh` stays `12/12`, and the current
    `run-parity-suite.sh` run remains green. See
    [§Phase 3 + 4 continuation (2026-04-14 third session)](#phase-3--4-continuation-2026-04-14-third-session).
- [x] Phase 4 — All 83 test cases from [Planned Test Catalogue](#planned-test-catalogue)
  implemented as Go + testify tests, compiling with
  `go build -tags integration ./...` and passing against the legacy
  stack with `go test -tags integration -v -run ^TestParitySuite$
  ./...`. The CLANG block (rows 49–60), AGG block (rows 61–67), SUB
  block (rows 68–75), and ENT block (rows 76–83) must each reach 100%
  green before Phase 5 can start capturing goldens for them.
  - [x] **Base-endpoint slice (2026-04-14):** 18 tests — rows 1–10
    (every base parity-contract endpoint) + validation rows 11/16/29
    - anonymous sub-case — implemented against the Step 2 bespoke
    smoke fixtures; `go build -tags integration ./...` + `go vet`
    exit 0; full suite PASS on two consecutive runs. See
    [§Phase 4 + 5 + 6 — Base-endpoint slice (2026-04-14)](#phase-4--5--6--base-endpoint-slice-2026-04-14).
  - [x] **Fixture-dependent slice (2026-04-14 closure):** rows 12–48
    plus CLANG / AGG / SUB / ENT are all implemented. The final
    legacy runner output is `Parity suite passed: 130/130 cases green.`
    on both cold and warm runs. The last cold-only flake
    (`agg-two-predicates` clause order) was closed by canonicalizing
    the top-level comma-delimited RSQL union for that single sub-case
    in the comparator.
- [x] Phase 5 — `GoldenComparator` (using `github.com/google/go-cmp`
  per **D-M** confirmed by owner iteration 8 Q2) + record-mode guard +
  golden files committed under `tests/parity/suite/testdata/golden/`
  with **per-sub-case granularity per D-X** (`127` files total;
  exact count recorded in the Execution Report). Every
  golden-asserted sub-case has a corresponding file; the 3
  exception-asserted rows (11, 16, 29) have no golden but the tests
  still pass.
  - [x] **Base-endpoint slice (2026-04-14):** 15 goldens captured
    under `tests/parity/suite/testdata/golden/` covering rows
    1/2/3/4/5/6/7/8/9/10 (per-sub-case granularity — e.g. row 2
    has 5 files). Stability check (second run without record mode)
    shows zero diff. Realm user UUIDs pinned to
    `00000000-0000-0000-0000-0000000001xx` so the rendered
    `rsqlFilterCondition` golden survives `down -v` cycles.
  - [x] **Fixture-dependent slice (2026-04-14 closure):** remaining
    bulk, preview, full-policy SUB, and ENT goldens were recorded.
    Total tree size after the closure run is `127` JSON goldens under
    `tests/parity/suite/testdata/golden/`; there are `0`
    `*.observed.json` sidecars after the second non-record stability run.
- [x] Phase 6 — `tests/parity/scripts/run-parity-suite.sh` runs the
  full bring-up → smoke → seed → suite → report pipeline and exits
  cleanly on success. The script prints
  `Parity suite passed: 130/130 cases green.` as its final line.
  - [x] **Script landed (2026-04-14):** `run-parity-suite.sh`
    implements bring-up → health wait → smoke.sh pre-flight → Go
    suite → canonical success line. The final script now counts only
    leaf sub-cases and prints `Parity suite passed: 130/130 cases green.`
- [x] Phase 7 — **Task-done gate per D-W** (final re-close on
  2026-04-14 after O6 iteration-11 landing commit `c8fbd84` +
  independent validation review. Timeline: F1 + O1–O5 closed in
  `98b5520` + `1f06e0c`; Phase 7 re-opened iteration 10 for **O6**;
  iteration 11 extended O6 to include `smoke.sh` deletion + the
  four-phase SetupSuite execution order (smoke seed → smoke run →
  wipe → main seed → tests); O6 landed as `c8fbd84` with all 12
  O6.1–O6.12 sub-items closed; post-landing independent cold/warm
  reruns this session produced `Parity suite passed: 130/130 cases
  green.` with the `[paritysuite] smoke phase: 12/12 assertions
  green` D-H compliance line present in every run. Cold `45.65s`,
  warm `1.47s`, `0` `*.observed.json` sidecars, `git status --short
  tests/parity` clean, `.run` debug config unaffected. See
  [Validation follow-ups §O6](#o6--move-simplified-policy-seeding-and-smoke-checks-out-of-compose-into-test-setupsuite-post-closure-architectural-follow-up-2026-04-14-iteration-10-extended-in-iteration-11)
  for the full 12-item close-out log, the iteration-11 execution
  order, and the **D-H** amendment text):
  - [x] First run in record mode captured goldens.
  - [x] Goldens landed under `tests/parity/suite/testdata/golden/`
    and are not `.gitignore`d (exist on disk with 127 files + 0
    observed sidecars after warm run).
  - [x] Second and third full runs **without** record mode produce the
    same `Parity suite passed: 130/130 cases green.` line (verified
    empirically against the working-tree state).
  - [x] No `*.observed.json` sidecars or post-record drift remain after
    the second non-record run (stability check — verified against
    working-tree state).
  - [x] `tests/parity/README.md` extended with run instructions,
    record mode, golden location, covered-scenario matrix, and
    pointer to Step 4.
  - [x] Parent plan Step 3 row flipped to `[x]` with links to the Go
    module, run script, golden directory, and seed extension.
  - [x] Execution Report at the bottom of this file filled with
    implemented changes, wall-clock times for cold and warm runs
    (warm must be **≤15 minutes** per **D-Y**; escalate as OQ if not),
    golden file count, total Go test count (larger than 83 due to
    **D-X** sub-tests — may be ~120+), and remaining `Open Questions`
    (OQ-SUITE-6/8/9 expected to resolve during Phase 1; anything else
    that surfaces during execution).
  - [x] `Decisions` section has D-I filled with the actual Go module
    path chosen at Phase 2 time.
  - [x] **F1 — Goldens, test files, and Phase 3 fixtures committed
    to git** (the formal **D-W point 2 + point 4** gate against
    *committed state*, not just on-disk state). Closure landed in
    commit `98b5520`; post-commit cold/warm reruns stayed green and
    the golden tree is clean. Checklist closure log lives under
    [Validation follow-ups §F1](#f1--commit-all-phase-36-artefacts-closed-d-w-point-2).
  - [x] **O1–O5 — Polish follow-ups closed**. Non-blocking but
    required per **D-W** point 6 ("Execution Report filled with
    no open gaps"). See
    [Validation follow-ups §O1–O5](#o1--test-file-naming-divergence-low-priority-cleanup)
    for the five-item closure log (test-file naming, named-leaf /
    `s.Run` acceptance, `83/83`→`130/130` proofread, license-expiry
    caveat in `tests/parity/README.md`, D-R wipe-and-reseed wiring in
    `run-parity-suite.sh`).
  - [x] **O6 — Move simplified-policy seed AND smoke checks from
    compose into Go `SetupSuite`** (post-closure architectural
    follow-up, added in iteration 10, extended in iteration 11 to
    include smoke). Unifies fixture ownership and the smoke
    pre-flight under the Go suite, deletes `smoke.sh` / `ac-seed`
    / `seed-access-control.sh`, and collapses `run-parity-suite.sh`
    into `docker compose up -d` → wait healthy → `go test`. Option
    **(b.ii)** locked by iteration-11 owner extension with the
    explicit SetupSuite execution order: **smoke seed → smoke run
    → wipe → main seed → tests**. **Blocks Step 4 drafting per
    D-Q**. Close-out gate lives under
    [Validation follow-ups §O6](#o6--move-simplified-policy-seeding-and-smoke-checks-out-of-compose-into-test-setupsuite-post-closure-architectural-follow-up-2026-04-14-iteration-10-extended-in-iteration-11):
    12-item sub-checklist from O6.1 (decision locked) through
    O6.12 (landing commit). **D-H is amended** by this refactor:
    smoke compliance check moves from `bash smoke.sh` output to the
    Go SetupSuite phase 2 log line
    `[paritysuite] smoke phase: 12/12 assertions green`. Post-O6
    revalidation (O6.9) must reproduce the committed `130/130`
    baseline with zero diff against the existing golden tree —
    if it doesn't, O6 is a regression and must be rolled back,
    not landed.

### Transport Convention Inventory

Filled by Phase 1 (2026-04-14) per **D-A** / **D-V**. Citations are
rooted in `sample-sources/access-control-spring-libs/access-control-client/`
(thin client) and `sample-sources/access-control-java-libs/access-control-policy-decision-point/`
(shared transport + DTOs). The Go helper layer lives in
`tests/parity/suite/helpers.go` and `tests/parity/suite/wire_v1.go` /
`tests/parity/suite/wire_v2.go`; response DTOs live in
`tests/parity/suite/model/`.

**Scope of Phase 1:** the inventory below covers rows 1–10 of the
parity-contract Summary Table (the only rows the Go HTTP helper layer
implements directly). Rows 11+ in the Planned Test Catalogue layer on
top of rows 1–10 (validation fixtures, CLANG / AGG / SUB / ENT) and
reuse the same helpers with different fixture + assertion shapes, so
they do not add new wire conventions.

### Row → Helper → Struct map

| Parity row | Method + path template                                                                                        | Client callsite (thin-client)                                                                                                                                            | Server handler                                                              | Request body                                                                                                                                                                                         | Response decode (client)                                                                                                                                                                                                                                                                                                               | Go helper                                                                     | Go response struct                                                                      |
| ---------- | ------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------- | --------------------------------------------------------------------------------------- |
| 1          | `GET /api-version`                                                                                            | `SpringApiVersionService.getApiVersion` (SpringApiVersionService.java:36-61) driven by `AbstractApiVersionService.isApiAvailable` (AbstractApiVersionService.java:23-58) | `ApiVersionResource.getApiVersion` (ApiVersionResource.java:14-35)          | empty                                                                                                                                                                                                | server `ApiVersionResponse{specs:List<ApiVersionSpec>}` with **integer** `major`/`minor`/`supportedMajors` (ApiVersionSpec.java:12-17) — client coerces to strings via `@JsonProperty("specs")` on `ApiVersionResponse{specifications}` (client ApiVersionResponse.java:14-18)                                                         | `HelperApiVersion(ctx)`                                                       | `model.ApiVersionResponse` (integer-typed per **D-V** item 11)                          |
| 2          | `POST /access/v1/check/resource?tenant_id={t}[&userId={u}]`                                                   | `RemoteACCommon.checkResourceV1` (RemoteACCommon (v1):48-54)                                                                                                             | `CheckEndpoint.checkResource` (CheckEndpoint.java:77-95)                    | `CheckAccessRequest{operation,type,resource}` (AbstractCheckAccessRequest.java:11-31)                                                                                                                | `Boolean` via `BOOLEAN_RESPONSE_TYPE` (RemoteACCommon (v1):34-54); empty body → `null` → `false`                                                                                                                                                                                                                                       | `HelperCheckResourceV1(ctx, req, tokens, customHeaders)`                      | `bool`                                                                                  |
| 3          | `POST /access/v1/check/resource/bulk?tenant_id={t}[&userId={u}]`                                              | `RemoteACCommon.checkResourcesV1` (RemoteACCommon (v1):56-62)                                                                                                            | `CheckEndpoint.checkResourceBulk` (CheckEndpoint.java:97-115)               | JSON array of `CheckAccessRequestWithId{id,operation,type,resource}` `@JsonInclude(NON_NULL)` (AbstractCheckAccessRequestWithId.java:14-36)                                                          | `Set<String>` via `SET_RESPONSE_TYPE` (wire is `LinkedHashSet`-ordered `String[]`, client discards order)                                                                                                                                                                                                                              | `HelperCheckResourcesV1(ctx, bulk, tokens, customHeaders)`                    | `[]string` (order preserved from server; compared via `cmpopts.SortSlices` per **D-M**) |
| 4          | `POST /access/v1/check/resource/bulk/operations?tenant_id={t}[&userId={u}]`                                   | `RemoteACCommon.checkResourcesByOperationsV1` (RemoteACCommon (v1):64-70)                                                                                                | `CheckEndpoint.checkResourceBulkOperations` (CheckEndpoint.java:117-135)    | JSON array of `AbstractCheckAccessBulkOperationsRequest{id,operations,resource,type}` `@JsonInclude(NON_NULL)` (…BulkOperationsRequest.java:20-49)                                                   | `Map<String,Set<String>>` via `MAP_RESPONSE_TYPE`                                                                                                                                                                                                                                                                                      | `HelperCheckResourcesByOperationsV1(ctx, bulk, tokens, customHeaders)`        | `map[string][]string`                                                                   |
| 5          | `POST /preview/v1/check/resource/bulk/operations?tenant_id={t}[&userId={u}]`                                  | `RemoteACCommon.checkResourcesByOperationsV1` with `Flags.withPreview()` resolving `PREVIEW_CHECK_RESOURCES_BY_OPERATIONS_V1` (AbstractRemoteACCommon (v1):51-67)        | `PreviewEndpoint.previewAccessBulk` (PreviewEndpoint.java:46-65)            | same as row 4                                                                                                                                                                                        | same as row 4                                                                                                                                                                                                                                                                                                                          | `HelperPreviewCheckResourcesByOperationsV1(ctx, bulk, tokens, customHeaders)` | `map[string][]string`                                                                   |
| 6          | `POST /access/v1/check/filter?tenant_id={t}&resourceType={rt}&operation={op}[&userId={u}]`                    | `RemoteACCommon.filterV1` (RemoteACCommon (v1):72-78)                                                                                                                    | `CheckEndpoint.filter` (CheckEndpoint.java:137-182)                         | empty body (POST w/ no `@Consumes`; client sends `HttpEntity<Object>` with null body)                                                                                                                | `EvaluationResultImpl` (EvaluationResultImpl.java:10-32) remapped into `OldFilterEvaluationResult` (OldFilterEvaluationResult.java:13-25); shared JSON field names (`calculationResult`, `filterCondition`, `mongodbFilterCondition`, `rsqlFilterCondition`, `sqlFilterCondition`, `customFilterCondition`)                            | `HelperFilterV1(ctx, resourceType, operation, userID, tokens, customHeaders)` | `model.OldFilterEvaluationResult`                                                       |
| 7          | `POST /access/v2/check/resource?tenant_id={t}[&userId={u}]&obligations={bool}`                                | `RemoteACCommon.checkResourceV2` (RemoteACCommon (v2):48-59)                                                                                                             | `CheckEndpointV2.checkResource` (CheckEndpointV2.java:79-95)                | `CheckResourceRequest{operation,type,resource}` (CheckResourceRequest.java:12-29)                                                                                                                    | `CheckResourceResponse{decision,[obligations]}` (CheckResourceResponse.java:16-41); `obligations` is `@JsonInclude(NON_NULL)`                                                                                                                                                                                                          | `HelperCheckResourceV2(ctx, req, tokens, customHeaders)`                      | `model.CheckResourceResponse` (Obligations ignored via cmpopts per **D-E**)             |
| 8          | `POST /access/v2/check/resource/bulk/operations?tenant_id={t}[&userId={u}]&obligations={bool}`                | `RemoteACCommon.checkResourcesV2` (RemoteACCommon (v2):61-72)                                                                                                            | `CheckEndpointV2.checkResourceBulkOperations` (CheckEndpointV2.java:97-113) | `CheckResourcesRequest{type,entries[]}` with `CheckResourcesRequestEntry{id,operations,resource}` `@JsonInclude(NON_NULL)` (CheckResourcesRequest.java:17-35, CheckResourcesRequestEntry.java:18-35) | `CheckResourcesResponse{decision:Map<String,Set<String>>,[obligations]}` (CheckResourcesResponse.java:18-37)                                                                                                                                                                                                                           | `HelperCheckResourcesV2(ctx, req, tokens, customHeaders)`                     | `model.CheckResourcesResponse` (Obligations ignored)                                    |
| 9          | `POST /preview/v2/check/resource/bulk/operations?tenant_id={t}[&userId={u}]&obligations={bool}`               | `RemoteACCommon.checkResourcesV2` with `Flags.withPreview()` resolving `PREVIEW_CHECK_RESOURCES_BY_OPERATIONS_V2` (AbstractRemoteACCommon (v2):45-61)                    | `PreviewEndpointV2.previewAccessBulk` (PreviewEndpointV2.java:54-75)        | same as row 8                                                                                                                                                                                        | same as row 8                                                                                                                                                                                                                                                                                                                          | `HelperPreviewCheckResourcesV2(ctx, req, tokens, customHeaders)`              | `model.CheckResourcesResponse` (Obligations ignored)                                    |
| 10         | `POST /access/v2/check/filter?tenant_id={t}&resourceType={rt}&operation={op}[&userId={u}]&obligations={bool}` | `RemoteACCommon.filterV2` (RemoteACCommon (v2):74-85)                                                                                                                    | `CheckEndpointV2.filter` (CheckEndpointV2.java:115-130)                     | empty body                                                                                                                                                                                           | `FilterResponse{calculationResult,filterCondition,mongodbFilterCondition,rsqlFilterCondition,sqlFilterCondition,customFilterCondition,[obligations]}` (FilterResponse.java:18-66); `calculationResult` annotation is `@JsonProperty(value="calculationResult", index=0)` on `Effect effect`; `obligations` is `@JsonInclude(NON_NULL)` | `HelperFilterV2(ctx, resourceType, operation, userID, tokens, customHeaders)` | `model.FilterResponse` (Obligations ignored)                                            |

### D-V wire-item check table

Every D-V item (1–14) below is confirmed against a concrete source
citation and bound to a single Go enforcement point. No new items
surfaced during Phase 1 reading beyond what D-V already drafted.

| D-V item | Wire behavior                                                                                                                                                                                                                                                                                                                                                                                  | Source citation                                                                                  | Go enforcement point                                                                                                                                                                                                                                                                                                                                                      |
| -------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1        | `Content-Type: application/json` on every body-bearing request; set unconditionally in the `prepareHeaders` helper.                                                                                                                                                                                                                                                                            | SpringRemoteACCommon.java:24-36                                                                  | `helpers.go` → `buildRequest()` sets `req.Header.Set("Content-Type", "application/json")` for every body-bearing helper; never set for `HelperApiVersion` (GET, empty body).                                                                                                                                                                                              |
| 2        | `Authorization: Bearer <M2M>` on every request (including `Authorization-Type: anonymous`).                                                                                                                                                                                                                                                                                                    | M2MOAuth2ClientInterceptor.java:21-52                                                            | `helpers.go` → `applyAuthHeaders(req, tokens)` reads `tokens.M2M` and sets `Authorization`.                                                                                                                                                                                                                                                                               |
| 3        | `Incoming-Token: Bearer <end-user>` on non-anonymous requests (omitted on anonymous flows).                                                                                                                                                                                                                                                                                                    | M2MOAuth2ClientInterceptor.java:28-42                                                            | `helpers.go` → `applyAuthHeaders` sets `Incoming-Token` when `tokens.EndUser != ""` and `tokens.Anonymous == false`.                                                                                                                                                                                                                                                      |
| 4        | `Authorization-Type: anonymous` on anonymous requests (and no `Incoming-Token`).                                                                                                                                                                                                                                                                                                               | SpringRemoteACCommon.java:17-30                                                                  | `helpers.go` → `applyAuthHeaders` sets `Authorization-Type: anonymous` when `tokens.Anonymous == true` and ensures `Incoming-Token` is absent.                                                                                                                                                                                                                            |
| 5        | `HeadersFilter.filterHeaders` drops caller-supplied headers whose name (case-insensitive) matches `authorization` or `tenant`.                                                                                                                                                                                                                                                                 | HeadersFilter.java:17-29, ProhibitedHeaders.java:11-22                                           | `helpers.go` → `filterCustomHeaders(m)` strips `authorization` / `tenant` (ASCII-lowercased keys) before calling `req.Header.Set` for each pass-through header. Row 48 of the catalogue asserts a 401 outcome against a caller that tried to stuff `authorization: bogus` into the custom-headers map — the helper drops it, the legacy M2M token wins, and parity holds. |
| 6        | `tenant_id` query param always present (possibly empty). Sourced from `TenantProvider.provide()`, null rendered as empty string.                                                                                                                                                                                                                                                               | AbstractGeneralRemoteACCommon.java:21-25, AbstractRemoteACCommon (v1):13-24                      | `helpers.go` → `buildQuery()` always appends `tenant_id=<cfg.TenantID>` (empty string when unset).                                                                                                                                                                                                                                                                        |
| 7        | Optional `userId` query param when on-behalf-of flow is used.                                                                                                                                                                                                                                                                                                                                  | AbstractRemoteACCommon (v1):13-24                                                                | `helpers.go` → `buildQuery()` appends `userId=<opts.UserID>` when non-empty; otherwise absent.                                                                                                                                                                                                                                                                            |
| 8        | v1 bulk arrays `@JsonInclude(NON_NULL)`; `null` fields must be omitted by the client encoder.                                                                                                                                                                                                                                                                                                  | AbstractCheckAccessRequestWithId.java:14-36, AbstractCheckAccessBulkOperationsRequest.java:20-49 | `model/check_resource.go` / `model/check_resources.go` request structs use `omitempty` on pointer-optional fields (`ID *string`) so `json.Marshal` drops nils.                                                                                                                                                                                                            |
| 9        | v2 query string always carries `obligations={bool}` from `Flags.obligations()`. Parity runs pin it to `obligations=false` per **D-E**.                                                                                                                                                                                                                                                         | AbstractRemoteACCommon (v2):18-43, Flags.java:6-66                                               | `wire_v2.go` → every v2 helper builds `v.Set("obligations", "false")` unconditionally. A `Flags` Go struct is **not** reproduced — the suite only uses `obligations=false` + per-test preview flag, so the helpers take a `Flags{Preview bool}` value and route to the preview path templates when `Preview==true`.                                                       |
| 10       | v1 filter response JSON field names: `calculationResult`, `filterCondition`, `mongodbFilterCondition`, `rsqlFilterCondition`, `sqlFilterCondition`, `customFilterCondition`. Client deserializes `EvaluationResultImpl` and immediately adapts to `OldFilterEvaluationResult`, which keeps the same Jackson aliases.                                                                           | EvaluationResultImpl.java:10-32, OldFilterEvaluationResult.java:13-25                            | `model/filter.go` → `OldFilterEvaluationResult` struct with `json:"calculationResult"`, `json:"filterCondition"`, `json:"mongodbFilterCondition"`, `json:"rsqlFilterCondition"`, `json:"sqlFilterCondition"`, `json:"customFilterCondition"`. `customFilterCondition` is `json.RawMessage` (legacy is a free-form `CustomFilterConditionImpl` polymorphic type).          |
| 11       | `/api-version` response uses **integer** `major`/`minor`/`supportedMajors`; client code uses strings, Jackson coerces. Authoritative shape is integer.                                                                                                                                                                                                                                         | ApiVersionSpec.java:12-17, parity contract Q1 resolution                                         | `model/api_version.go` → `ApiVersionResponse{Specs []ApiVersionSpec}` with `Major int`, `Minor int`, `SupportedMajors []int`. `Specs` carries `json:"specs"` to match the legacy server's on-the-wire field name.                                                                                                                                                         |
| 12       | v1 `CheckAccessRequest` body shape: `{"operation":"<op>","type":"<rt>","resource":<any>}`. Server side has no `@JsonProperty(required=true)` enforcement beyond client-side validator. Row 11 exercises empty `operation` and expects HTTP 400 from server-side `CheckRequestValidator.validateInputParameters` — reachable in Go because there is no client-side pre-validator short-circuit. | AbstractCheckAccessRequest.java:11-31, CheckRequestValidator.java:31-44                          | `model/check_resource.go` → `CheckAccessRequest{Operation, Type, Resource}` with `json` tags `operation`, `type`, `resource`. `Resource` is `any` (marshals arbitrary objects).                                                                                                                                                                                           |
| 13       | v1 bulk body: JSON array of `{"id","operation","type","resource"}` with `@JsonInclude(NON_NULL)`. Row 16 sends duplicate `id` values and expects HTTP 400 from `CheckRequestValidator` (`NotUniqueResourcesIdsException`).                                                                                                                                                                     | AbstractCheckAccessRequestWithId.java:14-36, CheckRequestValidator.java:76-94                    | `model/check_resource.go` → `CheckAccessRequestWithID` struct; `ID *string` with `omitempty` so nil ids are dropped.                                                                                                                                                                                                                                                      |
| 14       | Filter query params: `tenant_id`, required `resourceType`, optional `operation`, optional `userId`. Row 29 omits `resourceType` and expects HTTP 400 (`@NotNull @QueryParam("resourceType")`).                                                                                                                                                                                                 | CheckEndpoint.java:137-182, CheckEndpointV2.java:115-130                                         | `helpers.go` → `HelperFilterV1` / `HelperFilterV2` accept `resourceType` + `operation` + `userID` as separate args; callers that want to exercise row 29 pass an empty `resourceType` and assert the 400 at the response layer (no client-side pre-validator).                                                                                                            |

### Legacy semantics sub-section (grounded Phase 1 findings)

These findings back row-level design decisions that otherwise would
be speculative. They do not change wire behavior — they only unlock
fixture design and assert shape.

1. **Anonymous subject handling (row 4 grounding for D-K).** Reading
   `access-control-app/` confirmed the thin client emits
   `Authorization-Type: anonymous` and no `Incoming-Token`; the server
   side still requires a valid M2M bearer (the token is consumed by
   Quarkus security before the endpoint runs). The resulting subject
   that reaches the policy engine is the anonymous principal
   constructed inside the legacy Netcracker security-core SPI chain —
   an identity with **no** realm roles, no claims, and no
   `entitledResources`. Practical consequences for the suite: (a) a
   row with `roles: [ROLE_PARITY_READER]` will **always** DENY under
   anonymous flow because the principal has no roles; (b) the only
   allow paths for anonymous are global-access-policy rows
   (`resourceType=ALL + operation=ALL`, explicit role list — must
   include the "anonymous" internal role name if the server emits one,
   otherwise anonymous stays locked out) or explicit
   "component=ALL, resourceType=ALL, operation=ALL" global markers.
   Row 4 therefore asserts "anonymous allow" through a
   bespoke global-access fixture seeded with whatever role name Phase
   3 reads out of `NetcrackerAnonymousSubjectFactory` (symbol name
   verified at Phase 3 time; reading `access-control-app/` in Phase 1
   found only the `@Anonymous` Jakarta binding, not the concrete
   principal builder). **This does not block Phase 2** — the Go
   helper layer just sets the headers; the "which role does anonymous
   carry" question is a Phase 3 fixture-design question.
2. **Wildcard-role acceptance (OQ-SUITE-4).** Phase 1 re-verified the
   closure of D-S against BaseSimplifiedPolicy.java:27
   and SimplifiedPolicyMappingService.java:225-232
   — legacy format has no role-level wildcard construct. D-S holds;
   no fixtures or rows depend on this being re-opened.
3. **Condition AST grammar (OQ-SUITE-6).** Deferred to Phase 3; the
   reference sheet of operator spellings is a Phase-3 fixture-design
   input, not a Phase-1 helper-design input. The Go helper layer does
   not touch condition strings — it only ferries them as opaque
   `rsqlPredicate` / `sqlFilterCondition` / `mongodbFilterCondition`
   fields inside the filter response structs.
4. **Template substitution semantics (OQ-SUITE-9).** Same disposition
   as OQ-SUITE-6: a Phase-3 fixture-input task. D-T locks the
   server-side-render premise.
5. **Policy aggregation semantics (OQ-SUITE-8).** Deferred to Phase 3.
6. **Mock PIP control surface shape — IMPORTANT CORRECTION** (see
   **OQ-SUITE-10** below). The real pipstub control surface at
   `tests/integration/pipstub/main.go` is **not** shaped as D-O
   speculated. Phase 1 read the binary end-to-end and discovered:
   1. The control surface lives at `PUT/POST /pip-stub/configure`
      ([pipstub/main.go:52, 162-183](../../../test/integration/pipstub/main.go#L52)),
      not at `POST /__mock__/responses`. The body is a JSON **array**
      of `pipRoute` objects, each `{"path":"<literal>","responses":[{"statusCode":<int>,"body":<any>,"bodyRaw":"<string>"}]}`
      ([pipstub/main.go:12-21](../../../test/integration/pipstub/main.go#L12-L21)).
   2. The reset endpoint is `GET /pip-stub/reset`
      ([pipstub/main.go:51, 152-160](../../../test/integration/pipstub/main.go#L51)).
      It clears the `calls` slice and the `counters` map, but it
      **does not clear the `routes` map**. Previously-configured
      routes persist across resets; the only way to "unregister" a
      route is to re-`configure` the same path with a new response
      set (there is no `DELETE` endpoint).
   3. Path matching is **literal** against `r.URL.Path`
      ([pipstub/main.go:110](../../../test/integration/pipstub/main.go#L110));
      there is no templated / regex / wildcard matching. Registering
      `/api/v3/user-entitlements/user/{userId}` would match exactly
      that string and **not** `/api/v3/user-entitlements/user/42`.
   4. `body` accepts arbitrary JSON shapes via the Go `any` field
      ([pipstub/main.go:14](../../../test/integration/pipstub/main.go#L14));
      `bodyRaw` gives a raw-string escape hatch for shapes Go cannot
      express natively.
   5. `GET /pip-stub/calls` ([pipstub/main.go:50, 142-150](../../../test/integration/pipstub/main.go#L50))
      returns the ordered list of observed calls (path + method, no
      headers in the current binary).
   The consequences for Phase 2 and later phases are tracked in
   **OQ-SUITE-10** below. For Phase 2 the impact is narrow: the Go
   `pip_control.go` helper calls the corrected endpoints, supports
   one-shot pinning via `/pip-stub/configure`, and documents the
   "routes persist across reset" caveat at the top of the file so
   Phase 4 test authors know to overwrite (not delete) previous
   pins. `POST /__mock__/responses` references anywhere else in the
   handover are inherited from the D-O draft and are to be read as
   `PUT /pip-stub/configure`.
7. **Entitlements wire shape (D-U).** Reading `EntitlementsServiceImpl.java`
   and `EntitlementsPipServiceImpl.java` (per pre-read items 12–13
   of the companion prompt) confirms the four EA endpoints D-U
   enumerates. The path-templated requirement for
   `/api/v3/user-entitlements/user/{userId}` collides with pipstub's
   literal-path matching; see **OQ-SUITE-11** below. No Phase 2
   blocker — the ENT block lands in Phase 3 and Phase 4.
8. **Seed idempotency (OQ-SUITE-5).** Reading
   `seed-access-control.sh` (later removed)
   confirms it is a one-shot container that runs once when the
   compose stack comes up (`ac-seed` exits 0 after seeding) and
   does not self-guard against re-seeding. The Phase 3 wipe-and-
   reseed path from **D-R** runs as a separate script invoked by
   `run-parity-suite.sh`, not as an edit to this script. D-R is
   unchanged.

## Decisions

The decisions below are pre-locked by the parent plan owner and must not
be reopened during execution. **D-I is the only decision still open to
the executor** — it covers the Go module path chosen at Phase 2 time.
D-A..D-H were locked in iteration 1 (with **D-A** completely rewritten
in iteration 7 — Go + testify, see the D-A entry itself); D-J..D-Q were
locked in iteration 5; D-R..D-T followed in the same iteration's
follow-up answers; **D-U was locked in iteration 6** when the owner
asked for entitlements coverage; **D-V and D-W were locked in iteration 7**
alongside the D-A rewrite; **D-X, D-Y, D-Z were locked in iteration 8**
(sub-test granularity, wall-clock budget, CI out of scope). Together
they cover scope calls the executor cannot make unilaterally
(language/framework, module location, v2 strategy, anonymous parity,
seed namespace, golden typing, test-user strategy, mock PIP state,
`customFilterCondition` scope, Step 4 handover timing, seed idempotency,
wildcard-role removal, SUB block retention, entitlements PIP via mocked
`entitlements-aggregator`, parity-contract D4 rewritten as "capture the
API behavior the client uses, language-agnostic", task-done gate,
per-sub-case golden granularity, ≤15-minute warm-run SLA, CI out of
scope). Any additional decision the executor discovers at runtime goes
under `Open Questions` first and is only promoted here after the parent
plan owner locks it in.

- **D-A (language and framework — Go + testify, iteration 7 pivot).**
  The suite is a **Go** module using
  `github.com/stretchr/testify/suite` + `github.com/google/go-cmp/cmp`
  for deserialized-object comparison, following the established
  `tests/integration/testify/` pattern. **Why:** the parent plan owner
  explicitly locked Go + testify in iteration 7, overriding the
  iteration-1 Java choice. The owner wants a single Go-based
  integration-test toolchain across the repo; running a Java Maven
  module next to the existing Go testify suites would split the
  developer experience and require two toolchains in CI. **How this
  reconciles with parity contract D4 (see D-V).** Go cannot link
  `sample-sources/access-control-spring-libs/access-control-client/`
  (it is a Spring-wired Java JAR with no Go binding), so the suite
  **does not use the thin client at all**. Instead, Go tests drive
  the legacy AC HTTP surface directly, replicating every transport
  convention documented in the parity contract's §Transport
  Conventions Common to All Endpoints (Incoming-Token relay,
  Authorization-Type: anonymous, tenant_id query param, userId query
  param, HeadersFilter prohibited-header list, JSON request body
  shapes, DTO response structures). Phase 1 produces a **complete
  wire-convention inventory** that the Go HTTP helper layer
  implements verbatim — every header, every query param, every
  content-type, every JSON field — with a citation back to the parity
  contract row or the legacy thin-client source that documents it
  (see `EntitlementsPipServiceImpl.java`, `SpringRemoteACCommon.java`,
  `M2MOAuth2ClientInterceptor.java`, `CheckRequestValidator.java`,
  `AbstractRemoteACCommon.java` and friends under
  `sample-sources/access-control-spring-libs/access-control-client/`).
  Any wire behavior the Go helper misses is a test-coverage gap, not
  a parity property gap — so Phase 1 evidence discipline is
  load-bearing. **Rejected alternatives (iteration 7 re-review):**
  - Java Maven + JUnit 5 + AssertJ + thin-client JAR (iteration-1
    D-A) — **rejected** by the owner in iteration 7 in favor of the
    unified Go toolchain.
  - Shell out from Go to Java thin-client via a sidecar process —
    rejected because it double-wraps the transport conventions and
    makes failure debugging painful (you would have to debug both
    the Go test harness and the Java sidecar).
  - Reuse the existing `tests/integration/testify/` suite directly —
    rejected because that suite is the Authz Agent runtime test
    harness and has a different fixture / token / compose boundary;
    the parity suite is a sibling Go module, not a subdirectory of
    `tests/integration/testify/`.
- **D-B (module location — Go module at `tests/parity/suite/`).** The
  suite lives at `tests/parity/suite/` as a self-contained Go module
  (own `go.mod` and `go.sum`) adjacent to `tests/parity/compose/` and
  `tests/parity/scripts/`. **Why:** keeps every parity artefact under
  one root per the parent plan's Notes section item 3. A self-
  contained module avoids cross-module imports from
  `tests/integration/testify/` (shared helpers are **copied**, not
  imported — see **D-I** for why). **Rejected alternatives:**
  - Add parity tests under `tests/integration/testify/` as a new test
    suite — rejected because it conflates the Authz Agent runtime
    test harness with the parity harness; the parent plan keeps
    `tests/parity/` strictly separate from `tests/integration/`.
  - `tests/parity/compose/suite/` — rejected because `compose/` is
    reserved for Docker / seed / IdP fixtures in Step 2.
- **D-V (transport convention inventory is the parity-property source
  of truth).** Iteration 7 clarified (confirmed by owner in iteration
  8 Q1 = "rewrite D4"): the parity property is "the HTTP API
  behavior the thin client uses", and the parity contract's
  ../parity/access-control-client-api-surface.md §Decisions D4
  was **rewritten** to state this explicitly (earlier revisions
  conflated the goal with one possible implementation — "use the JAR").
  D-V of this handover is the operational consequence: the Go suite
  reimplements every transport convention the thin client speaks,
  sourced from a Phase 1 reading of
  `sample-sources/access-control-spring-libs/access-control-client/`
  as **reference material** (not as a dependency). The parity
  property holds at the HTTP boundary if and only if Phase 1 produces
  a complete wire-convention inventory and the Go helper layer
  enforces every item. **Why the Java JAR was never a correctness
  requirement:** the thin-client JAR's job was to document the wire
  protocol the parity suite must speak; the iteration-1 D-A picked
  Java because it naively inherited the "unmodified JAR" framing of
  D4; iterations 7 and 8 corrected both the handover and the parity
  contract to match the actual goal. **What the rewrite changes for
  specific parity contract items:**
  - D4 (rewritten in iteration 8 to "capture the API behavior the
    client uses, language-agnostic") — Go code replicates the wire
    protocol described by the thin client's source code, satisfying
    the rewritten D4 verbatim.
  - D5 (GENERAL PIPs mandatory) — unchanged; covered by the GENERAL
    PIP rows 7–10, 14–15, 27–28, 33–34, 45–46.
  - D1 (deserialized-object parity) — unchanged; Go `encoding/json`
    into Go structs is the equivalent of Jackson into Java DTOs. See
    **D-M** for the Go struct model.
  - D6 (ACMockServer not authoritative) — unchanged; Phase 1 grounds
    Go structs in the **real** legacy server source, not in
    `ACMockServer`.
  **Wire-behaviors Phase 1 MUST inventory** (cite the parity contract
  §Transport Conventions + relevant legacy source file):
  1. `Content-Type: application/json` on every body-bearing request
     (`SpringRemoteACCommon.prepareHeaders:24-36`).
  2. `Authorization: Bearer <M2M>` header on every request
     (`M2MOAuth2ClientInterceptor:21-52`).
  3. `Incoming-Token: Bearer <end-user>` header on non-anonymous
     requests (same reference).
  4. `Authorization-Type: anonymous` header on anonymous requests
     with **no** `Incoming-Token` (`SpringRemoteACCommon:17-30`).
  5. `HeadersFilter.filterHeaders` strips `authorization` and
     `tenant` (case-insensitive) from caller-supplied headers
     (`HeadersFilter:17-29`); the Go helper **must** strip the same
     names before sending, so a Go test that passes these as custom
     headers does not actually emit them. Row 48 is re-framed per
     this override — see row 48 description.
  6. `tenant_id` query param always present (possibly empty), sourced
     from `TenantProvider.provide()`
     (`AbstractGeneralRemoteACCommon:21-25`).
  7. Optional `userId` query param when on-behalf-of flow is used.
  8. v1 bulk arrays use `@JsonInclude(NON_NULL)` — the Go helper
     must omit `null` fields.
  9. v2 calls set `obligations={bool}` query param via `Flags`
     (`AbstractRemoteACCommon (v2):18-43`); the Go helper always
     sends `obligations=false` per **D-E**.
  10. v1 filter response deserializes as `EvaluationResultImpl` (not
      `OldFilterEvaluationResult` directly) and then maps; the Go
      struct mirrors the `EvaluationResultImpl` Jackson field names
      (`calculationResult`, `filterCondition`, `mongodbFilterCondition`,
      `rsqlFilterCondition`, `sqlFilterCondition`, `customFilterCondition`).
  11. `/api-version` response specs use **integer** `major`/`minor`/
      `supportedMajors`, not strings (parity-contract Q1 resolution);
      the Go struct uses `int`.
  12. `CheckAccessRequest` body: `{"operation":"<op>", "type":"<rt>",
      "resource":<any>}`. No `@JsonProperty(required=true)` validation
      on the Go side — Go tests send what they want and expect the
      legacy server to respond; server-side validation row 11 sends
      empty `operation` and expects HTTP 400 (reachable in Go because
      there is no client-side pre-validator to short-circuit it).
  13. Bulk request body: JSON array of
      `{"id","operation","type","resource"}` with `@JsonInclude(NON_NULL)`;
      row 16 sends duplicate ids and expects HTTP 400.
  14. Filter query params: `tenant_id`, required `resourceType`,
      optional `operation`, optional `userId`; row 29 omits
      `resourceType` and expects HTTP 400.
  Any Phase 1 finding that adds to this list is committed to the
  Transport Convention Inventory section (renamed from
  Thin-Client Inventory) below. Gaps found after Phase 4 tests are
  written are handled by extending the Go helper and re-running in
  record mode.
- **D-W (task-done gate: all tests green + all goldens committed).**
  Step 3 of the parent plan is considered **done** only when **all of
  the following hold simultaneously** on a clean checkout:
  1. The Go module at `tests/parity/suite/` builds with `go build
     ./...` exit code 0.
  2. `bash tests/parity/scripts/run-parity-suite.sh` brings the stack
     up, runs the full suite against the legacy reference stack, and
     prints `Parity suite passed: 130/130 cases green.` (or the
     current leaf-sub-case count if the catalogue is extended).
  3. A **second** run of the same script, immediately after the
     first, without record mode, prints the same line and produces
     **zero diff** against the committed golden tree. This proves
     the goldens are stable and not capturing non-deterministic
     server state.
  4. Every golden-asserted **sub-case** has a committed golden JSON
     file under `tests/parity/suite/testdata/golden/` per **D-X**
     sub-case granularity. The exact file count landed at `127`
     in the final Execution Report. Golden files are committed to
     the repo, not `.gitignore`d.
  5. The 3 exception-asserted validation rows (11, 16, 29) each
     produce the expected error shape from the legacy server and
     the test uses `testify.Error` / `assert.Contains` on the error
     string or status code — no golden JSON but the assertion is
     still green.
  6. The handover's `Done` checklist is **fully checked** (every
     `[ ]` flipped to `[x]`) and the Execution Report at the bottom
     of this file is filled with implemented changes, validation
     performed (including wall-clock times for cold and warm runs),
     and remaining gaps.
  7. The parent plan's
     20260413-access-control-parity-testing-plan.md
     Step 3 row is flipped to `[x]` and links the new Go module,
     run script, and golden directory.
  **Why the explicit gate:** previous iterations of this handover
  treated "handover drafted" as close-to-done. The owner clarified in
  iteration 7 that drafting the handover is **not** the deliverable;
  running the suite to green-and-stable with committed goldens is.
  This distinction matters because Step 4 strictly depends on the
  committed goldens existing; a drafted-but-unexecuted handover
  leaves Step 4 with nothing to re-assert against. **Rejected
  alternatives:**
  - Accept "handover drafted + fixtures written but not run" as
    done-enough — rejected because it invites Step 4 drafting to
    happen in parallel with fixture authoring, against **D-Q**.
  - Accept "some rows green, remaining rows flagged" as done —
    rejected because a partially green suite gives a false sense of
    parity coverage.
  **How to apply:** the Execution Report at the end of this file is
  mandatory, not optional. Phase 7 does not close until the
  Execution Report has wall-clock numbers and a confirmed
  `Parity suite passed: 130/130 cases green.` line observed twice in a
  row.
- **D-C (no CloudBSS bundle load).** Step 3 does **not** load
  `sample-sources/simplified-policy-sample/CloudBSS-simplified-policies.json`
  or `CloudBSS-simplified-pips.json` into the legacy stack. The parity suite
  is driven by bespoke fixtures under `tests/parity/compose/seed/policies/`
  that the suite itself owns end-to-end. **Why:** the parity contract covers
  behavior the thin client observes, not round-trip schema compatibility with
  the CloudBSS bundle. Mixing the two would dilute golden-file ownership and
  couple parity test coverage to the rotation cadence of the CloudBSS sample.
  **Rejected alternatives:**
  - Load CloudBSS in full — rejected because it adds unrelated policies to
    the decision surface, which makes the goldens noisier and harder to
    debug on mismatch.
  - Load a hand-picked subset of CloudBSS — rejected because any subset is
    effectively a bespoke fixture with extra indirection, and bespoke
    fixtures that live under `tests/parity/compose/seed/policies/` are
    clearer.
  **How to apply:** Phase 3 writes new fixtures under
  `tests/parity/compose/seed/policies/` only. `sample-sources/simplified-policy-sample/`
  stays a schema reference, unmodified.
- **D-D (golden file storage — Go `testdata/` convention).** Goldens live
  under `tests/parity/suite/testdata/golden/<endpoint>/<fixture>.json`,
  are committed to the repo, and are the single source of truth that
  Step 4 re-asserts against. **Why:** Go's standard library convention
  (documented in `go help testflag`) is that any directory named
  `testdata` under a package is automatically ignored by `go build`
  and `go vet`, and is reserved for test fixtures. Goldens under
  `testdata/golden/` sit next to the tests that consume them with zero
  build-system interaction. Updated from iteration 1's
  `src/test/resources/golden/` path (which was Maven-specific before
  the iteration-7 Go pivot).
  **Rejected alternatives:**
  - Store goldens outside the Go module in a separate
    `tests/parity/goldens/` tree — rejected because the tests would
    then need an absolute-path lookup; `testdata/` is relative to the
    test source file and works without extra config.
  - Embed goldens via `//go:embed` into the test binary — rejected
    because record mode needs to write back to the same files, and
    embedded files are read-only.
- **D-E (v2 obligations filter).** The suite ignores the v2 `obligations`
  block on both sides of every comparison, and every v2 request sets
  `obligations=false` on the query string. **Why:** mandated by **D3** of
  the parity contract. **How to apply:** the Go HTTP helper always appends
  `?obligations=false` on v2 endpoint builders (`FilterResponse`,
  `CheckResourceResponse`, `CheckResourcesResponse`); the
  `GoldenComparator` passes `cmp.FilterPath` to drop the `Obligations`
  field on v2 Go structs unconditionally before calling `cmp.Diff`.
- **D-F (record mode is env-var guarded).** Record mode is controlled by
  the environment variable `PARITY_GOLDEN_RECORD=1`, and the test-suite
  base hook verifies `PARITY_PROFILE=legacy` at the same time. Any other
  profile (`authz-agent`, unset) aborts the test run at `SetupSuite` with
  a fatal error before any test executes. **Why:** baseline capture
  against Authz Agent in Step 4 would silently reset the parity contract,
  which is exactly the regression Step 4 is supposed to catch. **How to
  apply:** `ParitySuite.SetupSuite` reads `os.Getenv("PARITY_GOLDEN_RECORD")`
  and `os.Getenv("PARITY_PROFILE")`; if record mode is on and profile is
  not `legacy`, the suite fails fast with `t.Fatalf`. Updated from
  iteration 1's `-Dparity.golden.record=true` Maven-profile form.
- **D-G (Go toolchain on host, replicating tests/integration/testify).**
  The parity suite is run with `go test -tags integration ./...` on a
  host that has Go 1.22+ installed, matching the pattern the existing
  `tests/integration/testify/` suite already uses (verified against
  [tests/integration/testify/suite_test.go](../../../test/integration/testify/suite_test.go)).
  The runner script `tests/parity/scripts/run-parity-suite.sh`
  orchestrates `docker compose up -d` + seed + `go test` and is itself
  a plain bash script — no Dockerized-Maven wrapper. **Why:** iteration 7
  pivot to Go means the "no host JDK" rationale of iteration 1's D-G no
  longer applies. Go 1.22+ is already a baseline requirement for working
  on this repo (the existing Authz Agent Go code and the runtime testify
  suite both need it). The parity suite reuses that same baseline — no
  new toolchain is introduced. **Rejected alternatives:**
  - Dockerized Go runner (`docker run --rm golang:1.22-alpine go test
    ./...`) — rejected because iteration-7 feedback was "match the
    existing testify pattern", and that pattern runs Go on the host.
  - Dockerized Maven runner (iteration-1 D-G) — dead with the Go pivot.
  - Run the suite inside a new service in `docker-compose.yml` —
    rejected because running test orchestration inside Compose
    conflicts with the single-responsibility split between the stack
    (Step 2) and the driver (Step 3).
  **How to apply:** `run-parity-suite.sh` invokes
  `go test -tags integration -run 'TestParitySuite' -count=1 ./...`
  against the Go module at `tests/parity/suite/`. The `-tags integration`
  build tag matches `tests/integration/testify/suite_test.go:1` so the
  parity tests are only picked up when explicitly asked for — no
  incidental execution on a plain `go test ./...` from the repo root.
- **D-H (smoke compliance check must stay green across Step 3 seed work).**
  Before O6 this meant "keep Step 2 `smoke.sh` 12/12 green". After O6's
  owner-approved amendment, the same compliance check lives inside
  `ParitySuite.SetupSuite` phase 2: the suite must emit the literal log line
  `[paritysuite] smoke phase: 12/12 assertions green` before any test method
  runs. **Why:** Step 2 passed live bring-up on 2026-04-13 / 2026-04-14 after
  the Gap 5 / Gap 7 closure; any regression here reopens that history even if
  the full suite later passes. **How to apply:** on every lifecycle refactor,
  verify the full legacy run still contains the smoke marker and still reaches
  `130/130` green.
- **D-I (Go dependency strategy — self-contained module, copied helpers).**
  The parity Go module at `tests/parity/suite/` has its own `go.mod`
  and does **not** cross-import from `tests/integration/testify/`.
  Shared helper code (Keycloak token acquisition via
  `GetKeycloakToken` pattern, HTTP client setup with TLS-skip-verify,
  retry helpers, JSON pretty-diff helper) is **copied** from
  `tests/integration/testify/helpers.go` into
  `tests/parity/suite/helpers.go` with attribution in a package-level
  comment. **Why:** copy > import because (a) the two modules have
  different test fixtures and different compose boundaries, and a
  shared package would pull in `tests/integration/testify`'s
  test-setup side effects; (b) the parity suite's lifetime is
  independent of the runtime suite — refactoring one shouldn't break
  the other. Direct Go dependencies declared in `go.mod`:
  `github.com/stretchr/testify v1.9+`,
  `github.com/google/go-cmp v0.6+`, and
  `github.com/golang-jwt/jwt/v5` (for token-parsing assertions only,
  not issuance — tokens come from Keycloak via password grant).
  **Rejected alternatives:**
  - Import `tests/integration/testify` as a Go dependency — rejected
    because the target is `package runtimetest` (a test binary
    package), not an importable library, and converting it would
    affect runtime test runs.
  - Place the parity suite inside `tests/integration/testify/` as a
    new suite — rejected by parent plan Notes item 3 (parity
    artefacts under `tests/parity/`).
  - Use a third-party HTTP library (`resty`, `httpmock`) — rejected
    because the standard `net/http` is sufficient and adds zero
    external deps beyond testify+go-cmp.
  **How to apply:** Phase 2 runs
  `go mod init <module-path>` (module path chosen at Phase 2 time to
  mirror the existing test module structure — executor records it here).
  **Chosen module path (Phase 2 close, 2026-04-14):**
  `authz-agent/tests/parity/suite` — mirrors the existing
  `authz-agent/tests/integration/testify` module path so the two Go
  test modules stay lexically adjacent and reviewers can grep both
  with a single prefix.
- **D-J (v2 endpoints captured as reference now, implemented in Step 4).**
  Step 3 captures legacy v2 golden files for rows 30–46 as the
  parity reference **as-is**. Step 4 is responsible for implementing the
  v2 surface in Authz Agent — including extending the ADR-0049
  `/api-version` payload to advertise `/access` major 2 and `/preview`
  major 2 — so that the **same** golden set passes unchanged against the
  `parity-authz-agent` profile. **Why:** the parent plan owner wants the
  legacy v2 behavior locked as the parity reference while it is still
  observable; deferring the v2 fixture capture to a later step would
  lose access to the ground-truth source when the legacy reference
  stack is eventually retired. **Rejected alternatives:**
  - Skip v2 block in Step 3 and raise a separate handover once Authz
    Agent v2 surface lands — rejected because it leaves v2 golden shapes
    un-captured during the only window they can be read from the legacy
    server under this plan.
  - Per-endpoint ADR accepting the v2 synthetic-deny short-circuit —
    rejected because the owner explicitly wants v2 implemented, not
    deferred.
  **How to apply:** remove every "v2 synthetic deny expected in Step 4"
  marker from the catalogue and Scope Note #2; Scope Note #2 becomes a
  pre-committed Step 4 work item instead. No ADR is filed in Step 3 for
  v2 — the v2 implementation ADR (if any) is Step 4's problem.
- **D-K (anonymous parity is hard).** `Authorization-Type: anonymous`
  scenarios (rows 4, 13, 18, 20, 24, 32, 36, 38, 42) capture the legacy
  baseline as the reference, and Step 4 must make Authz Agent produce the
  deserialized-equal decision for every such fixture. Any divergence
  surfaced in Step 4 is a **code fix** on the Authz Agent side, not an
  ADR-backed deviation. **Why:** the parity contract's intent is to lock
  legacy behavior as the reference for every endpoint the thin client
  reaches, and anonymous is in-scope per §PIP Observability Note item 5.
  The owner explicitly confirmed in this iteration that Step 4 brings
  Authz Agent into alignment with whatever the legacy anonymous subject
  machinery does, not the other way around. **Rejected alternatives:**
  soft parity with per-endpoint ADRs, anonymous out of scope. **How to
  apply:** row 4 drops the "exact subject shape is a Phase 1 inventory
  item" hedge from its expected-response column; Phase 1 still reads the
  legacy anonymous handling so fixtures are designed compatibly, but the
  suite asserts parity unconditionally once the golden is captured.
- **D-L (single seed domain `PARITY`).** All Step 3 fixtures land in the
  same `PARITY` domain that Step 2 already seeds via
  `PUT /access/v1/simplifiedPolicies/domainPolicies/PARITY`. Per-test
  isolation is achieved at the **request** level: each test picks a
  distinct `(resourceType, operation, role, user, resource attributes)`
  tuple so its fixture does not interact with unrelated rows. **Why:** a
  single seed channel is simpler to debug, avoids cross-domain ordering
  issues at `PUT` time, and keeps the smoke-vs-suite boundary out of the
  seed layer. **Rejected alternatives:**
  - Per-block domains (`PARITY_CLANG` / `PARITY_AGG` / `PARITY_SUB`) —
    rejected because multiple seed calls require ordering guarantees the
    handover does not want to own.
  - Two domains (`PARITY` for smoke + `PARITY_SUITE` for Step 3) —
    rejected for the same reason, plus it splits ownership of the same
    domain namespace across Step 2 and Step 3.
  **How to apply:** Phase 3 writes a fixture catalogue where every row
  carries a **unique `resourceType` scoped name** (e.g.
  `PARITY_CLANG_STRING_EQ`, `PARITY_AGG_PRED_UNION`,
  `PARITY_SUB_SCALAR_STR`, `PARITY_SUB_SCALAR_NUM`, …) so two unrelated
  tests never share a `(resourceType, operation)` locator. The AGG block
  intentionally shares locators across 2+ rows — those shared locators
  are called out explicitly in each AGG row's description. Step 2 smoke
  fixtures keep their current locators (`PARITY_CUSTOMER`, `PARITY_ORDER`,
  `PARITY_PAYMENT`) unchanged so `smoke.sh` stays 12/12 green per **D-H**.
- **D-M (Golden = typed-Go-struct deserialization via encoding/json + go-cmp).**
  Golden files are read by `GoldenComparator` through
  `encoding/json.Unmarshal` into a **concrete Go struct** that mirrors
  the legacy thin-client's Jackson DTO field-by-field; the fresh
  response from the server is unmarshalled the same way;
  `github.com/google/go-cmp/cmp.Diff(golden, actual, filterOpts...)`
  compares the two structs field-wise. **Why:** type-strict comparison
  catches the class of regressions the parity contract's Q1
  (`/api-version` integer-vs-string disagreement) calls out and binds
  golden authorship to the legacy wire model. A generic `map[string]any`
  comparison would let a server-side shape drift (integer → string,
  array → single element, etc.) slip through. **Rejected alternatives:**
  - `map[string]any` / `json.RawMessage` recursive comparison —
    rejected as type-loose.
  - `reflect.DeepEqual` — rejected because it does not produce a
    human-readable diff on mismatch; go-cmp's `cmp.Diff` prints a
    field-path-annotated diff that is essential for debugging.
  **How to apply:** `GoldenComparator` owns a
  `map[ParityEndpointId]func() any` that returns a fresh zero-value
  struct pointer per row; the comparator `json.Unmarshal`s into the
  pointer and compares. Endpoint-to-Go-struct mapping (the Go structs
  live under `tests/parity/suite/model/` as one file per DTO, with a
  comment at the top citing the Jackson source class):
  | Parity row | Go struct                                                                                                                                                                                                  |
  | ---------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
  | 1          | `ApiVersionResponse{Specs []ApiVersionSpec}` with integer fields per **D-V** item 11                                                                                                                       |
  | 2          | `bool` (direct JSON Boolean)                                                                                                                                                                               |
  | 3          | `[]string` (allowed ids; set-equality comparison via `cmpopts.SortSlices`)                                                                                                                                 |
  | 4          | `map[string][]string` (operation → allowed ids, per-key sort)                                                                                                                                              |
  | 5          | same as row 4                                                                                                                                                                                              |
  | 6          | `OldFilterEvaluationResult{CalculationResult string; FilterCondition string; MongodbFilterCondition string; RsqlFilterCondition string; SqlFilterCondition string; CustomFilterCondition json.RawMessage}` |
  | 7          | `CheckResourceResponse{Decision bool}` (obligations filtered via go-cmp option)                                                                                                                            |
  | 8          | `CheckResourcesResponse{Decision map[string][]string}` (obligations filtered)                                                                                                                              |
  | 9          | same as row 8                                                                                                                                                                                              |
  | 10         | `FilterResponse{...same fields as row 6...}` (obligations filtered)                                                                                                                                        |
  Each Go struct has Jackson-compatible JSON tags (`json:"calculationResult"`
  etc.) matching the legacy wire field names verbatim, with a
  one-line comment citing the legacy Java class and source location.
  Sorted-slice comparison for rows 3, 4, 5, 8 uses
  `cmpopts.SortSlices(func(a, b string) bool { return a < b })` so
  order-insensitive comparisons don't produce false diffs; order-
  sensitive slices (filter predicates, audit ids) do not use this
  option. Each test passes its parity-contract row id to the
  comparator, not a Go struct reference — the mapping is the single
  place where struct-endpoint binding is defined, and an unknown row
  id fails fast at lookup time.
- **D-N (multiple fixed test users in `parity-realm.json`).** Phase 3
  extends `tests/parity/compose/idp-seed/parity-realm.json` additively
  with a fixed set of test users, one per role/claim profile the suite
  needs. Baseline set (Phase 1 must verify / refine against the actual
  catalogue):
  - `parity-reader` — realm roles `[ROLE_PARITY_READER]`; JWT claims
    `department=SALES`, `tier=GOLD`; default password grants for
    single-role scenarios.
  - `parity-reviewer` — realm roles `[ROLE_PARITY_REVIEWER]` (no
    `ROLE_PARITY_READER`); JWT claims `department=ENGINEERING`; drives
    AGG rows 61/62 and any row that needs a distinct Incoming-Token
    subject from the M2M client (row 47).
  - `parity-multi-role` — realm roles
    `[ROLE_PARITY_READER, ROLE_PARITY_REVIEWER]`; used where a single
    token must satisfy two different policy-row role filters
    simultaneously (AGG rows 66/67 bulk/per-op).
  - `parity-other` — realm roles `[ROLE_PARITY_OTHER]`; matches **no**
    seeded policy; used to prove deny paths (AGG row 62 where "user
    has neither role" is the precondition). Wildcard-role fast-path
    coverage is intentionally absent — per **D-S** the legacy
    simplified-policy format has no role-level wildcard construct.
  - `parity-anon-baseline` — seeded but **not** used by any test; present
    so that future tests that need a second "unrelated end user" have a
    second username to reach for without editing the realm.
  A new password-grant-capable OAuth2 client `parity-end-user` (separate
  from the Step 2 `parity-m2m` M2M client) is seeded in the same realm
  with `directAccessGrantsEnabled=true` and `publicClient=false` +
  client-secret, so `ParityTokenFactory.endUserToken(username)` can
  obtain end-user tokens via the Resource-Owner-Password-Credentials
  grant without touching the Keycloak admin REST API. Every password
  must satisfy the legacy `DEFAULT_PASSWORD_POLICY` (Step 2 Follow-up
  1.8). **Why:** a fixed realm snapshot is the most debuggable form of
  test-user state for parity work; dynamic user creation via admin REST
  adds an API surface that drifts between Keycloak versions, and a
  single multi-role user cannot express "this user has ROLE_A only" as a
  test precondition. **Rejected alternatives:**
  - One multi-purpose user — rejected because the AGG row 64/65 pair
    **requires** two distinct users whose role intersection is empty
    with each other.
  - Dynamic user creation via Keycloak admin REST in `SetupSuite` —
    rejected because the admin-REST surface is unstable across Keycloak
    versions and the Netcracker identity-provider fork specifically has
    a custom SPI chain (Step 2 Follow-up 1.8) whose admin path is
    load-bearing in ways Step 3 does not want to own.
  **How to apply:** Phase 3 edits `parity-realm.json` additively (Gap 7
  / Follow-up 8 compatibility: the `cloud-common` realm file is NOT
  edited; new test users live in the tenant `parity` realm only);
  `ParityTokenFactory` caches tokens per (client, username) pair and
  refreshes on expiry; every SUB/CLANG/AGG test class declares which
  user profile it wants via a Go `type UserProfile int` enum rather
  than a magic string.
- **D-O (mock PIP state via control surface only).** SUB rows 68–75, and
  any other row that pins a PIP response (rows 7/8, 9/10, 14, 15, 27,
  28, 33, 34, 45, 46, 55, 59), use the
  `POST /__mock__/responses` control surface on `pip-mock` in
  `SetupTest`. `tests/integration/pipstub/` stays **unmodified**; no
  new default handlers are added to its Go source. **Why:** zero code
  change in pipstub preserves `tests/integration/runtime/` compatibility
  (the other consumer per Step 2 **D-D**), and makes every test's PIP
  state explicit in its own setup — no hidden default that could change
  under a future pipstub refactor. **Rejected alternatives:**
  - Default handlers baked into `tests/integration/pipstub/main.go` for
    scalar/array shapes — rejected because it introduces a code change
    on a shared module and spreads fixture ownership across two repos.
  - Hybrid (defaults + control surface) — rejected because the two
    mechanisms coexisting make it hard to reason about which handler
    served a given request on failure.
  **How to apply:** Phase 1 verifies the control surface (`POST
  /__mock__/responses` or whatever `tests/integration/pipstub/main.go`
  actually exposes — grep at read-time) accepts a JSON body shaped
  `{"path": "...", "method": "...", "status": 200, "body": <arbitrary
  JSON>}` and that `<arbitrary JSON>` can be a scalar string, scalar
  number, scalar boolean, array, object, or `null`. If any of those
  shapes is rejected, a new Open Question is raised and `pipstub` is
  extended **additively** in Step 3 (new control routes or new payload
  fields, existing ones untouched) per Step 2 **D-D**. A
  `ParityMockPipController` helper wraps the HTTP calls so tests do not
  hand-roll the JSON; the helper resets all pinned responses in a suite-
  wide `TearDownTest` so no state leaks across tests.
- **D-P (`customFilterCondition` out of SUB scope).** The SUB block
  covers `rsqlPredicate`, `sqlFilterCondition`, and `mongodbFilterCondition`
  only. `customFilterCondition` is explicitly **not** covered by the SUB
  block in this handover. **Why:** `customFilterCondition` is a
  free-form JSON object on the legacy side (`OldFilterEvaluationResult.
  customFilterCondition`) rather than a templated string, and its
  template-substitution semantics are not documented in the parity
  contract, the legacy OpenAPI, or `docs/policy-format.md`. Adding a
  speculative SUB row without knowing the rendered shape would produce a
  golden that Step 4 would have no principled way to assert against.
  **Rejected alternative:** add row 80 `SUB-general-scalar-into-custom`
  as a Phase 1 inventory item — rejected because it turns into an
  open-ended research task that is outside the bounded scope of this
  handover. When the need arises, `customFilterCondition` gets its own
  follow-up handover whose Phase 1 is dedicated to understanding the
  field's substitution semantics. **How to apply:** Scope Note #10
  carries an explicit "`customFilterCondition` excluded, see D-P"
  sentence; the SUB block stops at row 75 (rows 76–83 are the ENT
  block per **D-U**, a different scenario class).
- **D-Q (Step 4 handover drafted only after Step 3 lands).** No Step 4
  handover is authored in this iteration. The Step 4 handover is
  written **only** after Step 3 has landed — i.e. the Go test module
  builds, the fixture pack is seeded, the 83-row catalogue is green
  against the legacy reference stack, and the goldens are committed to
  the repo. **Why:** Step 4's deliverables list and divergence backlog
  depend on the actual golden shapes captured in Step 3, which are
  currently only predicted. Drafting Step 4 now would bake those
  predictions into a contract and hide real surprises when the legacy
  server emits something the handover did not anticipate. **Rejected
  alternative:** draft Step 4 in parallel with placeholder golden
  paths — rejected because it dilutes responsibility and invites
  speculation about divergence shapes. **How to apply:** the parent
  plan's Step 4 row stays pointing at "handover TBD after Step 3
  close"; this handover's Execution Report explicitly lists the
  golden tree path(s) that the Step 4 handover author must read before
  authoring Step 4; and the Step 3 execution report captures the
  wall-clock time the legacy run took so Step 4 can budget for it.
- **D-R (seed idempotency: wipe-and-reseed on every run).** Every
  `go test` invocation of `TestParitySuite` now owns a clean PAP lifecycle via
  `ParitySuite.SetupSuite`: phase 1 wipes the `PARITY` domain and seeds the
  smoke fixtures, phase 3 wipes again, and phase 4 seeds the full main corpus.
  The wipe uses the legacy replace-all semantics of
  `PUT /access/v1/simplifiedPolicies/domainPolicies/{domain}` and
  `domainPIPs/{domain}` with empty JSON arrays, which
  `SimplifiedPolicyMappingService.updateSimplifiedConfiguration` at line 80 of
  SimplifiedPolicyMappingService.java
  treats as a full domain replace. Main seeding then bulk-loads simplified
  PIPs, simplified policies, and the regular full-policy slice. **Why:** every
  run starts from a known state so a developer who edits a fixture JSON and
  re-runs the suite sees the new result without `docker compose down -v` or a
  compose-side reseed helper. **Rejected alternative:** first-boot-only seed
  like Step 2's historical `ac-seed` path — rejected because Step 3's
  developer iteration cadence is higher than Step 2's (Step 2 was bring-up,
  Step 3 is test authoring). **How to apply:** `run-parity-suite.sh` only
  brings the stack up and waits for health; `SetupSuite` phases 1 + 3 + 4 own
  the wipe-and-reseed guarantee on every run. OQ-SUITE-5 is closed by this
  decision.
- **D-S (wildcard `roles: ["*"]` is NOT a legacy parity property —
  rows 5, 20, 31, 67 removed from the catalogue).** Phase 1 legacy
  reading confirmed that the simplified-policy format in legacy
  `access-control` has **no** role-level wildcard construct:
  1. BaseSimplifiedPolicy.java:27
     stores `roles` as a plain `List<String>` with no wildcard flag.
  2. SimplifiedPolicyMappingService.java:225-232
     renders the list verbatim into rule target
     `subject.roles CONTAINS ANY 'r1','r2',...` — `["*"]` becomes
     `subject.roles CONTAINS ANY '*'`, which matches only if a user's
     `subject.roles` contains the literal string `*` (no real user
     ever does).
  3. policy-wildcards/README.md
     documents wildcards as a feature of the `MATCH` operator on
     path/attribute fields, not on role lists.
  4. The only "wildcard-like" construct in legacy simplified format
     is the **global access policy** pattern (`component=ALL +
     resourceType=ALL + operation=ALL + no condition + no
     rsqlPredicate`, enforced by
     SimplifiedPolicyMappingService.java:173-175)
     — and **it still requires an explicit role list**. It is a
     resource/operation wildcard, not a role wildcard.
  Conclusion: Authz Agent's global-all-role fast path (the subject of
  20260407-global-all-role-fast-path-task.md)
  is an Authz Agent-side optimization with **no legacy counterpart**.
  Testing it against the legacy stack would require seeding
  `roles: ["*"]` which the legacy engine silently treats as a
  literal-string role name, giving a parity result of "both stacks
  return `false`" — a trivially true, meaningless parity. **Rows
  previously numbered 5 (PSUITE-2-wildcard), 20 (PSUITE-4-wildcard),
  31 (PSUITE-6-wildcard), and 67 (AGG-wildcard-wins-over-predicate)
  are removed from the Planned Test Catalogue.** Wildcard fast-path
  coverage lives in Authz Agent's own unit / integration suites
  (e.g. `tests/integration/testify/wildcard_access_test.go`) where
  it can be asserted against the Authz Agent decision shape without
  pretending there is a legacy parity property. **Why:** per the
  user's Q2 answer in owner iteration 5 ("если нельзя, то это не
  нужно тестировать"). **Rejected alternatives:**
  - Substitute the global-access-policy pattern (component=ALL) for
    the wildcard rows — rejected because global-access is a
    `(resourceType, operation)` wildcard, not a role wildcard, so it
    does not exercise the same Authz Agent fast-path code.
  - Seed a policy row per role in the realm to approximate the
    semantic — rejected as a brittle and incomplete surrogate.
  **How to apply:** catalogue drops the 4 wildcard rows and renumbers
  the remaining rows sequentially (75 PSUITE/CLANG/AGG/SUB rows after
  the iteration-5 removal, plus 8 ENT rows added in iteration 6 per
  **D-U** for a total of 83 rows). Cross-references to the removed
  rows are either deleted or redirected to the nearest relevant
  row. OQ-SUITE-4 is closed. OQ-SUITE-7 is closed because the
  wildcard-vs-predicate aggregation case it tracked no longer exists
  in the catalogue; the pure-OLS-row-vs-RLS-row case from row 68
  (renumbered row 64) is covered separately by OQ-SUITE-8.
- **D-T (SUB block retained — server-side substitution confirmed by
  owner).** Per Q3 of owner iteration 5, the parent plan owner
  confirmed that `${subject.<alias>}` placeholder substitution inside
  `rsqlPredicate` / `sqlFilterCondition` / `mongodbFilterCondition`
  happens **server-side** in legacy `access-control` during predicate
  rendering, not consumer-side in the thin client or calling
  services. **Why:** this answer is load-bearing for the entire SUB
  block (rows 68–75 in the renumbered catalogue). If substitution
  were consumer-side, the goldens would contain raw unrendered
  template strings and the whole block would collapse into a trivial
  file-passthrough test. Owner confirmation lets the block stay as
  drafted. **Rejected alternatives:**
  - Defer SUB block to a separate follow-up handover with dedicated
    Phase 1 — rejected because owner confidence is high enough to
    lock the architectural premise now.
  - Fall back to "parity on raw template string" — rejected because
    it would produce a false-positive green parity that hides real
    divergence.
  **How to apply:** SUB rows 68–75 (new numbering) keep their
  current description. Phase 1's legacy-engine reading pass still
  resolves OQ-SUITE-9 by locating the concrete renderer symbol (most
  likely `SimplifiedPolicyRenderer`, `PredicateTemplateRenderer`, or
  whatever the legacy engine calls it — grep at read-time) and
  documenting the escaping / quoting rules for scalar string,
  number, Boolean, array, and special-char values. The renderer
  reading is now a **Phase-1 inventory task**, not a gating
  architectural question — the block is guaranteed to exist, only
  its escaping details need to be captured. If the renderer turns
  out to live in a helper module that the Authz Agent `pip.rego`
  does not mirror exactly, that divergence becomes a Step 4 code-fix
  candidate (not an ADR-deviation candidate — D-T locks the
  parity-on-rendered-string expectation).
- **D-U (entitlements-aggregator is mocked; new ENT block covers it).**
  Per the parent plan owner ask in iteration 6, the parity suite must
  also cover **entitlements** — a special PIP category that legacy
  `access-control` reaches via the separate `entitlements-aggregator`
  service. The aggregator itself is **not** brought up: it has Kafka,
  Postgres, and definition-bootstrap dependencies that are out of
  scope for the parity stack. Instead, an `entitlements-mock` HTTP
  service is added to `tests/parity/compose/docker-compose.yml`
  alongside the existing `pip-mock` (constraint #6 explicitly allows
  new compose services with a documented decision — this is it).
  Wire shape the mock must implement (verified against
  EntitlementsServiceImpl.java:16-18
  and
  EntitlementsPipServiceImpl.java:76-201
  during Phase 1):
  1. `GET /api-version` — returns an `ApiVersionResponse` advertising
     `/api` `major=3, minor=0, supportedMajors=[1,2,3]` so legacy AC's
     `apiVersionService.isApiAvailable(eaAddress, "/api", "3")` probe
     returns `true` and the V3 code path is exercised. Tests that need
     the V1 fallback path (legacy `EntitlementsPipServiceImpl.collectV1Entitlements`)
     re-pin the `/api-version` response in `SetupTest` to drop major 3
     so the client falls back.
  2. `POST /api/v1/entitlements-aggregator/entitlements` — body
     `{"userId": "<id>"}`, header `Tenant: <tenantId>`; response is a
     JSON object shaped `Map<String, Map<String, Set<String>>>` keyed
     on resourceType → entitlement name → set of resource ids.
  3. `GET /api/v3/user-entitlements/user/{userId}?all={all}&definition_updated_when={dwhen}`
     — response `GetDirectUserEntitlementsResponse{entitlements[], definitions[], definitionUpdatedWhen}`;
     this is the path legacy AC actually uses on the V3 cache-miss
     branch, see `EntitlementsPipServiceImpl.sendGetUserEntitlementsAndDefinitionRequest:148-168`.
  4. `GET /api/v3/user-entitlements/user/{userId}/resource-type/{rt}/name/{name}`
     — same response shape; called per (resourceType, entitlement) pair
     when a definition cache hit forces a per-definition lookup
     (`EntitlementsPipServiceImpl.sendGetUserEntitlementsRequest:170-201`).
  Implementation choice for the mock: **same `pip-stub:local` binary as
  `pip-mock`**, brought up as a second compose service named
  `entitlements-mock` with its own DNS alias on the parity bridge
  network, controlled via the same `POST /__mock__/responses` control
  surface that **D-O** uses for `pip-mock`. **Why:** keeps mock
  ownership in one Go binary, no fork, no extra image tag. Phase 1's
  pipstub control-surface check (D-O) explicitly extends to verifying
  that the control surface accepts the EA paths above plus arbitrary
  body shapes (object, array of nested objects, etc.) — if it does
  not, an additive extension to `tests/integration/pipstub/` lands
  before Phase 3 per Step 2 **D-D**'s additive-extension allowance,
  same fallback rule as **D-O**.
  **Compose-level changes** (consolidated in Phase 3):
  - New service `entitlements-mock` with `image: pip-stub:local`,
    `container_name: parity-entitlements-mock`, `networks: [parity]`,
    healthcheck identical to `pip-mock`, host port published as
    `${PARITY_EA_PORT:-28092}` (next free after `PARITY_PIP_PORT=28091`)
    for direct debugging. Per **D-H** the existing services are not
    touched — this is purely additive.
  - On the `access-control` service env block, override two env
    vars: `ACCESS_CONTROL_ENTITLEMENTS_AGGREGATOR_URL=http://entitlements-mock:8080`
    (overrides the Step 2 `http://idp:8080` fast-fail dummy) and
    `ACCESS_CONTROL_ENTITLEMENTS_CACHE_ENABLED=false` (overrides the
    `true` default at
    application.yml:109).
    Cache-disable is mandatory: with the 2s default TTL
    (application.yml:108),
    `SetupTest`-pinned mock responses would not propagate
    deterministically — a previous test's cached entitlements would
    leak into the next test until TTL expiry.
  - Step 2 `smoke.sh` is unaffected: the four smoke fixtures do not
    use entitlements, and `access-control` boots fine with the env
    vars overridden (the new env values are valid; only the **target
    behavior** changes — which means smoke continues to be 12/12 green
    per **D-H**, verified before and after the env-var addition).
  **New test block ENT-\* (rows 76–83, 8 cases)** added at the end of
  the catalogue covering the 6 operators
  (`CONTAINS`/`NOT CONTAINS`/`IN`/`NOT IN`/`CONTAINS ANY`/`IS EMPTY`/`IS NOT EMPTY`),
  multi-entitlement `as(...)` lists, multi-resourceType disambiguation,
  empty-user-entitlements, and the V1-fallback path. Per the policy AST
  grammar at entitlements/README.md,
  entitlements are **only** addressable in the `condition` AST field —
  the `rsqlPredicate` template-substitution mechanism does not apply
  because `entitledResources` is a function-call form, not a placeholder
  attribute. Therefore every ENT row lives on
  `POST /access/v1/check/resource` (Boolean surface): the row's
  `condition` walks the entitledResources AST and reduces to true/false.
  No ENT row hits a filter endpoint or a v2 endpoint — extending ENT
  coverage to those is a separate follow-up handover when the need
  arises.
  **Why mocked, not real EA:** running the real `entitlements-aggregator`
  against the parity stack would require Kafka (deferred per Step 2
  **D-G**), at least one new Postgres database, the EA's bootstrap
  flow (entitlement-definition seeding via the Cypher-like syntax
  documented at
  entitlement-definitions/README.md),
  and a secondary identity-provider integration. None of that is
  observable through the thin client — the only observable thing is
  the legacy AC ↔ EA HTTP contract above, which the mock fully
  reproduces. **Rejected alternatives:**
  - Run the real `entitlements-aggregator` from
    `sample-sources/entitlements-aggregator/` — rejected because it
    drags Kafka and bootstrap complexity into the parity stack, both
    explicitly excluded by Step 2 **D-G**.
  - Mock entitlements at the legacy-AC bean layer (replace
    `EntitlementsPipServiceImpl` with a test double) — rejected
    because it requires modifying or shadowing legacy-AC source per
    bean injection, which collides with **D4** (no fork of the
    thin client; legacy AC stays as-is) and breaks the "thin client
    JAR is the boundary" principle.
  - Use a wholly separate mock binary under `tests/parity/eastub/` —
    rejected because the existing `pip-stub:local` already serves the
    parity stack and the EA mock is functionally similar (HTTP +
    fixture-driven responses); a second binary would split fixture
    state across two control surfaces.
  **How to apply:** Phase 3 extends compose, env vars, and the seed
  pack (one EA-aware policy per ENT row). Phase 1 adds reading
  `sample-sources/entitlements-aggregator/` (the EA service source —
  only enough to verify the wire shapes the mock implements match
  the real EA, no need to understand its internals) to the legacy
  engine reading pass. The mock's default `/api-version` response is
  hard-coded (always major 3) so tests that do not pin it still get
  the V3 path; tests that need V1 explicitly re-pin in their
  `SetupTest`.
- **D-X (sub-test granularity: individually named testify leaf per
  sub-case, one golden per sub-case).** Many catalogue rows have multiple
  sub-cases that move the truth value across an operator or mock
  boundary (CLANG-boolean-and's 4-entry truth table, every
  `token-pip` / `header-pip` row's allow+deny pair, AGG-condition-or-across-rows's
  3 tier values, ENT rows' 2–3 mock variants). Each sub-case is
  authored as a separately named testify leaf — either via a literal
  `s.Run("<sub-case-name>", func() { ... })` inside a Suite method or via a
  dedicated `func (s *ParitySuite) TestRow...()` method when the sub-case is
  clearer as its own Suite child — and has its **own committed golden file** at
  `tests/parity/suite/testdata/golden/<endpoint>/<row>/<sub-case>.json`.
  The final runner counts **leaf sub-cases**, not rows, so the
  `Parity suite passed: 130/130 cases green.` line reflects the total
  testify leaf footprint while the catalogue itself remains 83 rows.
  Total golden file count landed at **127** in the final Execution
  Report. **Why per-sub-case goldens:** failure
  isolation is the single most painful part of golden-file test
  maintenance; a row with 4 sub-cases packed into one golden makes
  `cmp.Diff` output a wall of text when one sub-case regresses,
  and the human has to manually figure out which sub-case is the
  offender. Individually named testify leaves name the failing sub-case in the test
  output (`FAIL: TestCLANG_BooleanAnd/active_true_verified_false`);
  one golden per sub-case makes the diff precise — one file, one
  truth value, one assertion. **Rejected alternatives:**
  - One golden per row containing a map `sub_case_name →
    expected_result` — rejected because `cmp.Diff` on the whole map
    obscures which key diverged; the diff output requires manual
    parsing.
  - One golden per row containing an ordered slice of
    `{input, expected_output}` tuples — same rejection reason as
    above plus the slice ordering becomes load-bearing.
  **How to apply:** every sub-case must appear as its own named leaf in
  `go test -v` output. Literal `s.Run("<name>", ...)` subtests and
  per-sub-case Suite methods are both acceptable patterns as long as they
  preserve leaf-level failure naming. Each leaf invokes the
  `GoldenComparator` with a golden path that includes the sub-case name
  segment (e.g.
  `golden/check-resource-v1/token-pip/allow.json` and
  `golden/check-resource-v1/token-pip/deny.json`); sub-case names
  are snake_case and stable across runs. The catalogue's "Golden file"
  column lists the **parent directory** for multi-sub-case rows
  (e.g. `golden/check-resource-v1/token-pip/`) and the single file
  path for single-case rows (e.g. `golden/check-resource-v1/allow-incoming.json`).
  Phase 4 can freely add sub-cases to rows where Phase 1 reading
  surfaces additional truth-boundary variants (e.g. CLANG-null-handling
  gains a third sub-case for "field present but explicit null" if the
  legacy engine distinguishes it from "field absent"), with each new
  sub-case committed as a new golden file and the row's "case count"
  in the execution report updated accordingly.
- **D-Y (wall-clock budget: ≤15 minutes warm run).** A warm run of
  `run-parity-suite.sh` (cached docker images, Step 2 stack already
  brought up once in this session) must complete in **under 15
  minutes wall-clock**, including the second run required by **D-W**'s
  stability check (so ≤7.5 minutes per single pass of up → smoke →
  seed → `go test`). Cold runs (first bring-up, Liquibase migration,
  JVM warm-up) have **no SLA** — the Execution Report just records
  the observed cold-run time for Step 4 budgeting. **Why 15 minutes:**
  Step 3 executor will run the suite many times during Phase 4
  authoring (iterate on fixtures, tweak helpers, re-run); a
  >15-minute warm cycle kills iteration cadence. A <5-minute budget
  would be ideal but is unrealistic given the seed wipe-and-reseed
  per **D-R** (each invocation re-PUTs the full fixture pack, which
  takes 10–30s on the legacy AC simplified-policy REST endpoint) plus
  the 83 HTTP request-reply cycles plus docker healthcheck waits.
  **Rejected alternatives:**
  - ≤5 minutes warm — rejected because wipe-and-reseed alone
    consumes a significant slice and the 83 HTTP calls add 15–30s
    each way; achievable only by skipping re-seed (would break
    **D-R**) or by parallelizing the tests (would break **D-O**
    mock-state isolation).
  - No SLA — rejected because it leaves the executor without a
    signal for "something is wrong" (e.g. seed loop stuck,
    Incoming-Token JWT expired mid-run).
  **How to apply:** Phase 7 Execution Report captures the observed
  cold-run and warm-run wall-clock times; if warm exceeds 15
  minutes, the executor escalates as an Open Question before closing
  Step 3. Phase 4 authoring can use `go test -tags integration -run
  ^TestParitySuite$/TestCheckResourceV1` (or similar narrow `-run`
  pattern) for faster inner-loop iteration without running the full
  suite every edit — the full `run-parity-suite.sh` is reserved for
  the stability check and for the final pre-commit run.
- **D-Z (CI integration is out of scope for Step 3).** Step 3 is
  **local-only** — `run-parity-suite.sh` is authored as a bash
  script a developer runs manually on a workstation with Go 1.22+,
  Docker, and the Step 2 `build-images.sh` outputs. No GitHub
  Actions / GitLab CI / Jenkins wiring is added in this iteration.
  **Why:** (a) the existing `tests/integration/runtime/` and
  `tests/integration/testify/` suites do not appear to have a
  wired-in CI config in the repo state the executor sees today —
  wiring the parity suite alone would be an isolated CI artefact
  without precedent; (b) CI integration has its own set of design
  questions (which runner image, Docker-in-Docker or remote Docker
  socket, how to surface golden diffs, how to fail the job on
  non-zero exit) that multiply Step 3's surface without adding
  parity value; (c) the owner explicitly deferred CI in iteration 7.
  **Rejected alternatives:**
  - Wire into CI immediately — rejected per owner answer.
  - Commit a draft GitHub Actions workflow with `if: false` guard
    — rejected because a guarded-off workflow is invisible in CI
    logs and confusing for future readers; a follow-up handover
    with the real wiring is cleaner.
  **How to apply:** `run-parity-suite.sh` is local-only; its README
  section explicitly says "run this manually on a workstation". A
  **future** CI integration is tracked as an explicit out-of-scope
  reminder in the parent plan and will live in a follow-up handover
  after Step 3 and Step 4 have both landed.

### Planned Test Catalogue

The table below enumerates every test case the suite must implement. IDs are of
the form `PSUITE-<endpoint-row>-<variant>`; the endpoint-row number is the `#`
column of the parity contract's Summary Table. Variants are grouped so a
reader can see at a glance that every mandatory dimension (OLS, RLS, wildcard,
TOKEN/HEADER/GENERAL PIP, Incoming-Token, anonymous, validation) is covered.

### Scope notes

1. **OLS vs RLS terminology.** In legacy `access-control` and in Authz Agent
   per ../policy-format.md §OLS/RLS Field Split, the
   OLS/RLS split is a **property of the simplified-policy row**, not of the
   endpoint. A row that has `resourceType + operation + roles` and **no**
   `condition` and **no** `rsqlPredicate`/`sqlPredicate`/`mongodbPredicate`
   is a pure OLS row. A row that additionally carries a `condition` AST or
   any predicate is RLS (and still participates in the OLS stage via its
   `roles` field). Every endpoint in the parity contract — including
   `POST /access/v1/check/resource` and its bulk variants, which return a
   Boolean rather than a materialized filter — evaluates **both** the OLS
   and the RLS stage; the difference between `check/resource` and
   `check/filter` is how the RLS stage is **surfaced** (collapsed to a
   Boolean vs. returned as a predicate bundle), not **whether** it runs.
   The catalogue therefore labels each fixture's "Policy coverage" column
   by the shape of the seeded row (OLS-only vs. RLS), not by the endpoint
   it is hit through. A TOKEN/HEADER/GENERAL PIP-driven `condition` on a
   policy row is always RLS, even when exercised through `check/resource`.
2. **v2 endpoints are captured now, implemented in Step 4 (per D-J).**
   Rows 30–46 hit the legacy v2 surface directly; Step 3 captures the
   deserialized goldens as the parity reference. Step 4 is responsible
   for implementing the v2 surface in Authz Agent and for extending
   ADR-0049's `/api-version` payload to advertise `/access` major 2 /
   `/preview` major 2, so that the thin-client's `isApiAvailable(...,
   "2")` probe returns `true` and the v2 calls reach Authz Agent rather
   than short-circuiting to the client's synthetic deny. This handover
   does not assert parity for v2 against Authz Agent — that is Step 4's
   problem — but the golden set is authoritative for both legacy and
   Authz Agent runs.
3. Rows that exercise TOKEN-PIP resolution rely on claims emitted by the
   parity IdP realm. If a scenario requires a claim not yet in
   `parity-realm.json`, Phase 3 extends the realm seed additively — never by
   replacing an existing claim.
4. Rows that exercise HEADER-PIP resolution use a custom header name that is
   not in `ProhibitedHeaders` (not `authorization`, not `tenant`, not
   `incoming-token`); the suggested default name is
   `x-parity-pip-attribute`.
5. Rows that exercise GENERAL-PIP resolution pin a deterministic mock PIP
   response via `POST /__mock__/responses` in `SetupTest`; the mock state
   is reset between tests.
6. Every fixture that sends an `Authorization: Bearer` header acquires the
   M2M token from the parity IdP `parity-m2m` client. Every fixture that
   sends an `Incoming-Token` header also acquires an end-user token from a
   dedicated `parity-end-user` password-grant-capable client seeded under
   `parity-realm.json` (Phase 3 adds this client if it does not already
   exist, additively to the existing Step 2 realm).
7. Validation fixtures are counted separately from success fixtures; they
   are asserted via testify's `assert.Equal(t, 400, resp.StatusCode)` +
   `assert.Contains(t, body, "<substring>")` on the HTTP status code and
   response body, not via golden JSON. Per the **D-A** / **D-V** Go
   pivot, the Go suite does **not** have the Java-side
   `CheckRequestValidator` short-circuit — **all three** validation
   rows (11 missing-operation, 16 duplicate-ids, 29 missing-resourceType)
   are now server-side tests that reach
   `AccessControlExceptionControllerAdvice` directly. This is strictly
   better coverage than the iteration-1 Java path would have had, where
   rows 11 and 16 short-circuited on the client side before any HTTP
   request and could not observe the server's error shape at all.
8. **Condition language coverage (CLANG-\*).** Rows 49–60 exercise the
   simplified-policy `condition` AST language itself — string/number
   equality and relational operators, `AND`/`OR`/`NOT`, `IN` against a
   literal collection vs. a PIP-backed collection, `CONTAINS ANY` /
   `CONTAINS ALL` on set-valued attributes, `null` handling, nested subject
   field access, and compound `rsqlPredicate` templates. These tests
   complement the scenario-level rows 2–51 which treat the condition as a
   black box; the CLANG rows instead pick one RLS row per language feature
   and drive two-or-more sub-cases that move the truth value across the
   operator boundary. Every CLANG row lives on `POST /access/v1/check/resource`
   (Boolean surface) unless the feature is only observable as a
   materialized predicate, in which case it moves to
   `POST /access/v1/check/filter`. The exact operator/keyword spelling the
   legacy engine accepts is a Phase 1 inventory item — see
   [Open Questions](#open-questions) OQ-SUITE-6. The golden captures
   whichever shape the legacy server emits; Step 4 asserts the same
   deserialized value against Authz Agent's OPA pipeline per **D1**.
9. **Policy combining / aggregation coverage (AGG-\*).** Rows 61–67 cover
   the behavior of multiple simplified-policy rows matching the same
   `(subject, resourceType, operation)` tuple. The parity baseline here is
   locked by [ADR-0025 (RLS Predicate OR Aggregation)](../../decisions) —
   the 20260326-rls-predicate-or-aggregation-task.md
   Authz Agent handover implements the canonical-side aggregation shape
   (`rsql` as `(p1),(p2),...`, type-local OR for `sql`/`mongodb`/`custom`).
   The AGG rows prove that the legacy `access-control` engine produces the
   *same* deserialized aggregation shape for identical fixtures; any
   divergence surfaced here is material and must be escalated rather than
   paved over. Scenarios cover: OR across roles (rows 61/62), OR across
   `rsqlPredicate` rows for the same `(resourceType, operation, role)`
   (row 63), pure OLS row + RLS row interaction on the same
   `(resourceType, operation, role)` without wildcards (row 64), OR across
   `condition` ASTs with different resource predicates (row 65),
   bulk-endpoint per-id aggregation (row 66), and per-operation
   aggregation on `check/resource/bulk/operations` (row 67). Wildcard-role
   combining scenarios are **not** present — per **D-S** the legacy
   simplified-policy format has no role-level wildcard construct so there
   is no legacy counterpart to capture. The exact wire shape of
   OLS-row-vs-RLS-row combining is a Phase 1 inventory item — see
   [Open Questions](#open-questions) OQ-SUITE-8.
10. **Predicate template substitution coverage (SUB-\*).** Rows 68–75
    cover the **template-substitution** mechanism that renders PIP values
    into predicate strings before they are returned to the caller. This is
    a distinct code path from the `condition`-AST evaluator that rows 5,
    6, 9, 25, 26, 47, 48 exercise — and the catalogue had it merged into
    those rows until this iteration. Per **D-T** (owner iteration 5) the
    substitution happens **server-side** in legacy `access-control` during
    predicate rendering — this is locked; Phase 1's only remaining SUB
    task is mapping the concrete renderer symbol and its escaping rules
    (OQ-SUITE-9). The two mechanisms differ:
    1. **AST evaluation** (existing rows): the `condition` AST walker
       reads `subject.<alias>` values at decision time. The PIP value is
       consumed but never serialized; the decision is a Boolean.
    2. **Template substitution** (this block): the `rsqlPredicate` /
       `sqlFilterCondition` / `mongodbFilterCondition` field on the
       simplified-policy row contains a `${subject.<alias>}` placeholder;
       the legacy engine substitutes the PIP value into the placeholder
       during predicate rendering and the **rendered string** is what
       `check/filter` returns to the caller in the
       `EvaluationResultImpl` / `FilterResponse` payload. Step 4 must
       produce a deserialized-equal rendered string from Authz Agent's
       predicate emitter.
    Per the user's ask, the SUB block has full coverage of GENERAL PIPs
    that return a **leaf / scalar** value (string, number, Boolean) — a
    return shape not covered by the existing array-returning (row 7) or
    dict-returning (row 9) GENERAL PIP rows. It also exercises
    substitution into two of the three non-RSQL predicate-string types
    (`sqlFilterCondition`, `mongodbFilterCondition`), the
    array-into-non-RSQL cross-product, the multi-PIP-in-one-template
    variant, and a special-character escaping fixture whose exact wire
    shape is a Phase 1 inventory item (OQ-SUITE-9).
    **`customFilterCondition` is explicitly excluded from the SUB block
    per D-P** — its legacy shape is a free-form JSON object rather than
    a templated string, and its template-substitution semantics are not
    documented; covering it requires a separate follow-up handover
    whose Phase 1 is dedicated to understanding that field. The SUB
    block stops at row 75; no SUB row for `customFilterCondition`.
11. **Entitlements coverage (ENT-\*).** Rows 76–83 cover the legacy
    `entitledResources` AST construct that resolves user-to-resource
    references through the **entitlements-aggregator** service. Per
    **D-U** the aggregator itself is **not** brought up (it requires
    Kafka, Postgres, and Cypher-like definition bootstrap, all out of
    scope for the parity stack); instead a new
    `entitlements-mock` compose service runs the same `pip-stub:local`
    binary on a separate DNS alias and exposes the four endpoints
    `GET /api-version`, `POST /api/v1/entitlements-aggregator/entitlements`,
    `GET /api/v3/user-entitlements/user/{userId}`, and
    `GET /api/v3/user-entitlements/user/{userId}/resource-type/{rt}/name/{name}`
    via the same `POST /__mock__/responses` control surface that
    **D-O** uses for `pip-mock`. Each ENT row pins a deterministic
    mock response in `SetupTest`. Coverage:
    1. `CONTAINS` / `IN` operator forms (rows 76, 77).
    2. Multi-entitlement `as('A','B')` list with union semantics (row 78).
    3. `CONTAINS ANY` set-intersection (row 79).
    4. `IS EMPTY` boundary (row 80).
    5. `NOT CONTAINS` negation (row 81).
    6. Multi-resourceType disambiguation via `of(<resourceType>)`
       (row 82).
    7. All-empty-user response (row 83).
    Per the AST grammar at
    entitlements/README.md,
    `subject.entitledResources` is a function-call form and is **only
    addressable inside the `condition` AST field** of a simplified-policy
    row — the `rsqlPredicate` template-substitution mechanism does not
    apply, so no SUB-style ENT row exists. Therefore every ENT row
    lives on `POST /access/v1/check/resource` (Boolean surface);
    extending ENT to filter / bulk / v2 endpoints is a separate
    follow-up handover when the need arises. Legacy AC's entitlement
    cache is **disabled** at the env level
    (`ACCESS_CONTROL_ENTITLEMENTS_CACHE_ENABLED=false` per **D-U**) so
    per-test pinning takes effect immediately.

### Test catalogue

| #   | Scenario ID                               | Parity row | Method + path                                                     | Auth variant                                                                                       | PIP                             | Policy coverage                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 | Expected response (legacy)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               | Golden file                                                                                                                                                               | ------------------------------------------------------------------------------- |
| --- | ----------------------------------------- | ---------- | ----------------------------------------------------------------- | -------------------------------------------------------------------------------------------------- | ------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------- |
| 1   | PSUITE-1-m2m                              | 1          | GET /api-version                                                  | M2M only                                                                                           | none                            | n/a (static handler)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            | `ApiVersionResponse` with integer-shape specs for `/access`, `/preview`, `/api`; deserializes into the client's string-field DTO per D1                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  | `golden/api-version/m2m.json`                                                                                                                                             | ------------------------------------------------------------------------------- |
| 2   | PSUITE-2-allow-incoming                   | 2          | POST /access/v1/check/resource                                    | Incoming-Token non-anonymous                                                                       | none                            | OLS allow (PARITY_CUSTOMER READ, ROLE_PARITY_READER)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            | `true`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   | `golden/check-resource-v1/allow-incoming.json`                                                                                                                            | ------------------------------------------------------------------------------- |
| 3   | PSUITE-2-deny-incoming                    | 2          | POST /access/v1/check/resource                                    | Incoming-Token non-anonymous                                                                       | none                            | OLS deny (PARITY_CUSTOMER WRITE, reader role)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   | `false`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  | `golden/check-resource-v1/deny-incoming.json`                                                                                                                             | ------------------------------------------------------------------------------- |
| 4   | PSUITE-2-anon                             | 2          | POST /access/v1/check/resource                                    | Authorization-Type: anonymous                                                                      | none                            | Dedicated policy row matching the "no end-user identity" subject class the legacy server derives from an anonymous M2M call. Per **D-K** anonymous parity is hard: the legacy decision is the authoritative reference and Step 4 brings Authz Agent into alignment through code fixes, not ADR-backed deviation. The fixture is designed so the legacy decision is deterministic (pure OLS match on whatever roles the legacy anonymous subject carries plus a negative control row that definitely does not match) — Phase 1 must grep `sample-sources/access-control-app/` for the `Authorization-Type: anonymous` handling to pick the right role set; the resulting decision is still captured verbatim into the golden. Proves parity-contract PIP-Observability-Note item 5.                                              | whichever Boolean the legacy server returns; captured in record mode and asserted unconditionally against Authz Agent on Step 4                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          | `golden/check-resource-v1/anon.json`                                                                                                                                      | ------------------------------------------------------------------------------- |
| 5   | PSUITE-2-token-pip                        | 2          | POST /access/v1/check/resource                                    | Incoming-Token non-anonymous                                                                       | TOKEN                           | **RLS row** (has `condition`) for PARITY_CUSTOMER READ / ROLE_PARITY_READER: the `condition` AST references `subject.parityDepartment` and the TOKEN-PIP declaration binds that attribute to a JWT claim (e.g. `department`) emitted by the parity IdP. Evaluated server-side by the simplified-policy engine; `check/resource` surfaces the RLS result as a Boolean rather than a predicate bundle. Two sub-cases: (a) Incoming-Token whose claim satisfies the condition — expect `true`; (b) claim does not satisfy — expect `false`. The OLS stage (`resourceType`/`operation`/`roles` match) is prerequisite; this test exercises the RLS-condition / TOKEN-PIP binding on top of a passing OLS check.                                                                                                                     | `true` for sub-case (a), `false` for sub-case (b)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        | `golden/check-resource-v1/token-pip.json`                                                                                                                                 | ------------------------------------------------------------------------------- |
| 6   | PSUITE-2-header-pip                       | 2          | POST /access/v1/check/resource                                    | Incoming-Token + custom header `x-parity-pip-attribute`                                            | HEADER                          | **RLS row** (has `condition`) with the `condition` AST referencing `subject.parityHeaderAttr`. The HEADER-PIP declaration binds that attribute to header `x-parity-pip-attribute` — name intentionally not in `ProhibitedHeaders` so `HeadersFilter` does not strip it (parity contract §Transport Conventions item 3). Two sub-cases: (a) header value satisfies the condition — `true`; (b) header value does not — `false`. Same RLS-on-check/resource surfacing as row 5.                                                                                                                                                                                                                                                                                                                                                   | `true` for sub-case (a), `false` for sub-case (b)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        | `golden/check-resource-v1/header-pip.json`                                                                                                                                | ------------------------------------------------------------------------------- |
| 7   | PSUITE-2-general-pip-list-allow           | 2          | POST /access/v1/check/resource                                    | Incoming-Token non-anonymous                                                                       | GENERAL (list return)           | **RLS row** with `condition` `resource.id IN subject.parityAllowed`. GENERAL-PIP returns a **JSON array** of allowed ids from `pip-mock`; the legacy PIP runtime stores the array under `subject.parityAllowed` and the condition AST reads it. `SetupTest` pins the mock to return `[<acting-subject-id>]`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    | `true` when the subject id is in the returned array                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      | `golden/check-resource-v1/general-pip-list-allow.json`                                                                                                                    | ------------------------------------------------------------------------------- |
| 8   | PSUITE-2-general-pip-list-deny            | 2          | POST /access/v1/check/resource                                    | Incoming-Token non-anonymous                                                                       | GENERAL (list return)           | Same RLS row as row 7; mock pinned to return `[]`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              | `false`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  | `golden/check-resource-v1/general-pip-list-deny.json`                                                                                                                     | ------------------------------------------------------------------------------- |
| 9   | PSUITE-2-general-pip-dict-allow           | 2          | POST /access/v1/check/resource                                    | Incoming-Token non-anonymous                                                                       | GENERAL (dict return)           | **RLS row** with `condition` referencing **direct leaf aliases extracted from a dict-returning GENERAL PIP via `jsonPath`**: `resource.department == subject.parityMetaDepartment AND resource.amount <= subject.parityMetaMaxAmount`. Legacy simplified-policy validation accepts direct PIP aliases only (not `subject.<pip>.<field>`), so the suite models dict-return coverage through multiple aliases resolved from the same JSON object returned by `pip-mock`, e.g. `{"department":"finance","ids":["..."],"maxAmount":1000}`. `SetupTest` pins the mock to the allow-shape. Purpose: exercise JSON-object GENERAL-PIP handling beyond the array path in row 7 while staying compatible with the legacy validator.                                                                                                      | `true` when the `resource.amount` is within the dict-returned budget and the department matches                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          | `golden/check-resource-v1/general-pip-dict-allow.json`                                                                                                                    | ------------------------------------------------------------------------------- |
| 10  | PSUITE-2-general-pip-dict-deny            | 2          | POST /access/v1/check/resource                                    | Incoming-Token non-anonymous                                                                       | GENERAL (dict return)           | Same RLS row as row 9; mock pinned to a deny-shape (`{"department": "OPERATIONS", "ids": [], "maxAmount": 0}`).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 | `false`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  | `golden/check-resource-v1/general-pip-dict-deny.json`                                                                                                                     | ------------------------------------------------------------------------------- |
| 11  | PSUITE-2-validation-missing-operation     | 2          | POST /access/v1/check/resource                                    | M2M + Incoming-Token                                                                               | none                            | n/a                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             | **Server-side** validation, reachable directly because the Go suite does not have a Java `CheckRequestValidator` short-circuit per **D-A** / **D-V**. The Go helper sends a raw POST body with an empty `operation` field (or omits it entirely); legacy AC's `AccessControlExceptionControllerAdvice` returns HTTP 400 with body `{"message": "Request body is not valid: 'operation' field is required"}`. Asserted via testify `assert.Equal(t, 400, resp.StatusCode)` + `assert.Contains(t, body, "operation")`. Note: the iteration-1 Java framing of this row (client-side throw via thin client) is no longer applicable — Go tests reach the server-side path that Java's CheckRequestValidator short-circuited. | HTTP 400 with `{"message": "..."}` body containing `'operation' field is required`                                                                                        | no golden (exception-asserted via testify assertion on status + body substring) |
| 12  | PSUITE-3-mixed                            | 3          | POST /access/v1/check/resource/bulk                               | Incoming-Token non-anonymous                                                                       | none                            | Mixed allow/deny across 4 ids, OLS                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              | `Set<String>` containing only the allowed ids, order-insensitive                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | `golden/check-resource-bulk-v1/mixed.json`                                                                                                                                | ------------------------------------------------------------------------------- |
| 13  | PSUITE-3-anon                             | 3          | POST /access/v1/check/resource/bulk                               | Authorization-Type: anonymous                                                                      | none                            | Anonymous subject class (see row 4)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             | `Set<String>` matching the legacy-baseline decision for the anonymous subject                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            | `golden/check-resource-bulk-v1/anon.json`                                                                                                                                 | ------------------------------------------------------------------------------- |
| 14  | PSUITE-3-general-pip-list                 | 3          | POST /access/v1/check/resource/bulk                               | Incoming-Token non-anonymous                                                                       | GENERAL (list return)           | Same RLS row as row 7 (`condition` referencing `subject.parityAllowed`, array PIP)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              | `Set<String>` containing only the ids the mock PIP round-trip allowed                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    | `golden/check-resource-bulk-v1/general-pip-list.json`                                                                                                                     | ------------------------------------------------------------------------------- |
| 15  | PSUITE-3-general-pip-dict                 | 3          | POST /access/v1/check/resource/bulk                               | Incoming-Token non-anonymous                                                                       | GENERAL (dict return)           | Same JSON-object GENERAL-PIP family as row 9, but consumed through direct leaf aliases (`subject.parityMetaIds` / `subject.parityMetaMaxAmount`) extracted from the same mocked object via `jsonPath`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           | `Set<String>` matching the dict-returning mock response                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  | `golden/check-resource-bulk-v1/general-pip-dict.json`                                                                                                                     | ------------------------------------------------------------------------------- |
| 16  | PSUITE-3-validation-duplicate-ids         | 3          | POST /access/v1/check/resource/bulk                               | M2M + Incoming-Token                                                                               | none                            | n/a                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             | **Server-side** validation, reachable directly (Go pivot per **D-A** / **D-V**). The Go helper sends a bulk request with two entries sharing the same `id`; legacy AC's `CheckRequestValidator.validateBulkRequestsV1` (which still runs server-side on the incoming request; the client-side copy of the same class is what the Java thin client uses as a pre-check) throws `NotUniqueResourcesIdsException` which `AccessControlExceptionControllerAdvice` surfaces as HTTP 400 body `{"message": "Bulk Check Resources request contains duplicated ids"}`. Asserted via testify `assert.Equal(t, 400, resp.StatusCode)` + `assert.Contains(t, body, "duplicated ids")`.                                              | HTTP 400 with body containing `duplicated ids`                                                                                                                            | no golden (exception-asserted)                                                  |
| 17  | PSUITE-4-mixed                            | 4          | POST /access/v1/check/resource/bulk/operations                    | Incoming-Token non-anonymous                                                                       | none                            | Per-operation OLS mix across 3 entries, 2 operations                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            | `Map<String, Set<String>>` with expected keys and allowed-id sets                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        | `golden/check-resource-bulk-ops-v1/mixed.json`                                                                                                                            | ------------------------------------------------------------------------------- |
| 18  | PSUITE-4-anon                             | 4          | POST /access/v1/check/resource/bulk/operations                    | Authorization-Type: anonymous                                                                      | none                            | Anonymous subject class                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | `Map<String, Set<String>>` matching the legacy baseline for the anonymous subject                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        | `golden/check-resource-bulk-ops-v1/anon.json`                                                                                                                             | ------------------------------------------------------------------------------- |
| 19  | PSUITE-5-mixed                            | 5          | POST /preview/v1/check/resource/bulk/operations                   | Incoming-Token non-anonymous                                                                       | none                            | Same body as PSUITE-4-mixed                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     | Same shape as PSUITE-4-mixed (audit-log skip is not observable over the wire)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            | `golden/preview-bulk-ops-v1/mixed.json`                                                                                                                                   | ------------------------------------------------------------------------------- |
| 20  | PSUITE-5-anon                             | 5          | POST /preview/v1/check/resource/bulk/operations                   | Authorization-Type: anonymous                                                                      | none                            | Same as PSUITE-4-anon                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           | Same shape as PSUITE-4-anon                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              | `golden/preview-bulk-ops-v1/anon.json`                                                                                                                                    | ------------------------------------------------------------------------------- |
| 21  | PSUITE-6-allow-incoming                   | 6          | POST /access/v1/check/filter                                      | Incoming-Token non-anonymous                                                                       | none                            | RLS filter returning `calculationResult=ALLOW` and a non-empty `rsqlPredicate`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  | `OldFilterEvaluationResult` with `effect=ALLOW` and the typed predicate populated                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        | `golden/check-filter-v1/allow-incoming.json`                                                                                                                              | ------------------------------------------------------------------------------- |
| 22  | PSUITE-6-use-filter-incoming              | 6          | POST /access/v1/check/filter                                      | Incoming-Token non-anonymous                                                                       | none                            | RLS filter returning `USE_FILTER_CONDITION` with `rsqlFilterCondition`, `sqlFilterCondition`, `mongodbFilterCondition` all populated                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            | `OldFilterEvaluationResult` with all four predicate fields set                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           | `golden/check-filter-v1/use-filter-incoming.json`                                                                                                                         | ------------------------------------------------------------------------------- |
| 23  | PSUITE-6-deny-incoming                    | 6          | POST /access/v1/check/filter                                      | Incoming-Token non-anonymous                                                                       | none                            | RLS DENY                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        | `OldFilterEvaluationResult` with `effect=DENY`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           | `golden/check-filter-v1/deny-incoming.json`                                                                                                                               | ------------------------------------------------------------------------------- |
| 24  | PSUITE-6-anon                             | 6          | POST /access/v1/check/filter                                      | Authorization-Type: anonymous                                                                      | none                            | Anonymous subject class                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | `OldFilterEvaluationResult` matching the legacy baseline for the anonymous subject                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       | `golden/check-filter-v1/anon.json`                                                                                                                                        | ------------------------------------------------------------------------------- |
| 25  | PSUITE-6-token-pip                        | 6          | POST /access/v1/check/filter                                      | Incoming-Token non-anonymous                                                                       | TOKEN                           | **RLS row** with `rsqlPredicate` template referencing `subject.parityDepartment` — same TOKEN-PIP binding as row 5, but the policy-row shape is a `rsqlPredicate` template rather than a `condition` AST, exercising the predicate-materialization path that `check/filter` surfaces verbatim                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   | `OldFilterEvaluationResult` with the rendered predicate bearing the JWT claim value                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      | `golden/check-filter-v1/token-pip.json`                                                                                                                                   | ------------------------------------------------------------------------------- |
| 26  | PSUITE-6-header-pip                       | 6          | POST /access/v1/check/filter                                      | Incoming-Token + custom header `x-parity-pip-attribute`                                            | HEADER                          | RLS `rsqlPredicate` template references `subject.parityHeaderAttr` — same HEADER-PIP binding as row 6                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           | `OldFilterEvaluationResult` with the rendered predicate bearing the header value                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | `golden/check-filter-v1/header-pip.json`                                                                                                                                  | ------------------------------------------------------------------------------- |
| 27  | PSUITE-6-general-pip-list                 | 6          | POST /access/v1/check/filter                                      | Incoming-Token non-anonymous                                                                       | GENERAL (list return)           | RLS `rsqlPredicate` `id=in=(${subject.parityAllowed})` — same array-PIP declaration as row 7                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    | `OldFilterEvaluationResult` with the rendered predicate bearing the mock-returned id array                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               | `golden/check-filter-v1/general-pip-list.json`                                                                                                                            | ------------------------------------------------------------------------------- |
| 28  | PSUITE-6-general-pip-dict                 | 6          | POST /access/v1/check/filter                                      | Incoming-Token non-anonymous                                                                       | GENERAL (dict return)           | RLS `rsqlPredicate` composed from direct aliases extracted out of the dict-returning PIP: `id=in=(${subject.parityMetaIds});amount=le=${subject.parityMetaMaxAmount}` — same JSON-object GENERAL-PIP declaration family as row 9, but projected into legacy-validator-compatible aliases via `jsonPath`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | `OldFilterEvaluationResult` with the rendered predicate reading multiple leaves of the dict                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              | `golden/check-filter-v1/general-pip-dict.json`                                                                                                                            | ------------------------------------------------------------------------------- |
| 29  | PSUITE-6-validation-missing-resource-type | 6          | POST /access/v1/check/filter                                      | M2M + Incoming-Token                                                                               | none                            | n/a                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             | **Server-side** validation: the `resourceType` query parameter is omitted from the Go helper call; the server's `@NotNull @QueryParam("resourceType")` constraint fires, producing HTTP 400 body `{"message": "..."}` via `AccessControlExceptionControllerAdvice` (parity contract §6.3). Since the Go pivot (D-A / D-V), rows 11 and 16 also reach server-side validation — so this is **one of three** server-side validation fixtures rather than "the only one". Asserted via testify `assert.Equal(t, 400, resp.StatusCode)` + `assert.Contains(t, body, "resourceType")`.                                                                                                                                         | HTTP 400 with `{"message": "..."}` body referencing `resourceType`                                                                                                        | no golden (exception-asserted)                                                  |
| 30  | PSUITE-7-allow-incoming                   | 7          | POST /access/v2/check/resource?obligations=false                  | Incoming-Token non-anonymous                                                                       | none                            | OLS allow (per D-J v2 is captured now, Step 4 implements the surface)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           | `CheckResourceResponse` with `decision=true`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             | `golden/check-resource-v2/allow-incoming.json`                                                                                                                            | ------------------------------------------------------------------------------- |
| 31  | PSUITE-7-deny-incoming                    | 7          | POST /access/v2/check/resource?obligations=false                  | Incoming-Token non-anonymous                                                                       | none                            | OLS deny                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        | `CheckResourceResponse` with `decision=false`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            | `golden/check-resource-v2/deny-incoming.json`                                                                                                                             | ------------------------------------------------------------------------------- |
| 32  | PSUITE-7-anon                             | 7          | POST /access/v2/check/resource?obligations=false                  | Authorization-Type: anonymous                                                                      | none                            | Anonymous subject class                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | `CheckResourceResponse` matching the legacy baseline                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     | `golden/check-resource-v2/anon.json`                                                                                                                                      | ------------------------------------------------------------------------------- |
| 33  | PSUITE-7-general-pip-list                 | 7          | POST /access/v2/check/resource?obligations=false                  | Incoming-Token non-anonymous                                                                       | GENERAL (list return)           | Same RLS row as row 7 (array PIP `subject.parityAllowed`)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       | `CheckResourceResponse` with `decision=true`/`false` matching the array mock                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             | `golden/check-resource-v2/general-pip-list.json`                                                                                                                          | ------------------------------------------------------------------------------- |
| 34  | PSUITE-7-general-pip-dict                 | 7          | POST /access/v2/check/resource?obligations=false                  | Incoming-Token non-anonymous                                                                       | GENERAL (dict return)           | Same RLS row family as row 9 (JSON-object GENERAL-PIP projected into `subject.parityMetaDepartment` / `subject.parityMetaMaxAmount`)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            | `CheckResourceResponse` with `decision` matching the dict mock                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           | `golden/check-resource-v2/general-pip-dict.json`                                                                                                                          | ------------------------------------------------------------------------------- |
| 35  | PSUITE-8-mixed                            | 8          | POST /access/v2/check/resource/bulk/operations?obligations=false  | Incoming-Token non-anonymous                                                                       | none                            | Per-operation mix                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               | `CheckResourcesResponse` `decision: Map<String, Set<String>>`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            | `golden/check-resource-bulk-ops-v2/mixed.json`                                                                                                                            | ------------------------------------------------------------------------------- |
| 36  | PSUITE-8-anon                             | 8          | POST /access/v2/check/resource/bulk/operations?obligations=false  | Authorization-Type: anonymous                                                                      | none                            | Anonymous subject class                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | Anonymous `CheckResourcesResponse`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       | `golden/check-resource-bulk-ops-v2/anon.json`                                                                                                                             | ------------------------------------------------------------------------------- |
| 37  | PSUITE-9-mixed                            | 9          | POST /preview/v2/check/resource/bulk/operations?obligations=false | Incoming-Token non-anonymous                                                                       | none                            | Same body as PSUITE-8-mixed                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     | Same shape (preview audit-log skip is not observable)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    | `golden/preview-bulk-ops-v2/mixed.json`                                                                                                                                   | ------------------------------------------------------------------------------- |
| 38  | PSUITE-9-anon                             | 9          | POST /preview/v2/check/resource/bulk/operations?obligations=false | Authorization-Type: anonymous                                                                      | none                            | Anonymous subject class                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | Anonymous response                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       | `golden/preview-bulk-ops-v2/anon.json`                                                                                                                                    | ------------------------------------------------------------------------------- |
| 39  | PSUITE-10-allow-incoming                  | 10         | POST /access/v2/check/filter?obligations=false                    | Incoming-Token non-anonymous                                                                       | none                            | RLS ALLOW with typed predicates                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 | `FilterResponse` with `calculationResult=ALLOW` and the predicate fields populated (obligations block ignored per D3)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    | `golden/check-filter-v2/allow-incoming.json`                                                                                                                              | ------------------------------------------------------------------------------- |
| 40  | PSUITE-10-use-filter-incoming             | 10         | POST /access/v2/check/filter?obligations=false                    | Incoming-Token non-anonymous                                                                       | none                            | USE_FILTER_CONDITION with all four predicate types                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              | `FilterResponse` with all four predicate fields set                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      | `golden/check-filter-v2/use-filter-incoming.json`                                                                                                                         | ------------------------------------------------------------------------------- |
| 41  | PSUITE-10-deny-incoming                   | 10         | POST /access/v2/check/filter?obligations=false                    | Incoming-Token non-anonymous                                                                       | none                            | RLS DENY                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        | `FilterResponse` with `calculationResult=DENY`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           | `golden/check-filter-v2/deny-incoming.json`                                                                                                                               | ------------------------------------------------------------------------------- |
| 42  | PSUITE-10-anon                            | 10         | POST /access/v2/check/filter?obligations=false                    | Authorization-Type: anonymous                                                                      | none                            | Anonymous subject class                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | Anonymous `FilterResponse`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               | `golden/check-filter-v2/anon.json`                                                                                                                                        | ------------------------------------------------------------------------------- |
| 43  | PSUITE-10-token-pip                       | 10         | POST /access/v2/check/filter?obligations=false                    | Incoming-Token non-anonymous                                                                       | TOKEN                           | Same TOKEN-PIP policy as row 25                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 | `FilterResponse` with predicate rendered from JWT claim                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  | `golden/check-filter-v2/token-pip.json`                                                                                                                                   | ------------------------------------------------------------------------------- |
| 44  | PSUITE-10-header-pip                      | 10         | POST /access/v2/check/filter?obligations=false                    | Incoming-Token + custom header                                                                     | HEADER                          | Same HEADER-PIP policy as row 26                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                | `FilterResponse` with predicate rendered from header                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     | `golden/check-filter-v2/header-pip.json`                                                                                                                                  | ------------------------------------------------------------------------------- |
| 45  | PSUITE-10-general-pip-list                | 10         | POST /access/v2/check/filter?obligations=false                    | Incoming-Token non-anonymous                                                                       | GENERAL (list return)           | Same array-PIP policy as row 27                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 | `FilterResponse` with predicate rendered from the array mock response                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    | `golden/check-filter-v2/general-pip-list.json`                                                                                                                            | ------------------------------------------------------------------------------- |
| 46  | PSUITE-10-general-pip-dict                | 10         | POST /access/v2/check/filter?obligations=false                    | Incoming-Token non-anonymous                                                                       | GENERAL (dict return)           | Same dict-PIP policy as row 28                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  | `FilterResponse` with predicate rendered from nested fields of the dict mock response                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    | `golden/check-filter-v2/general-pip-dict.json`                                                                                                                            | ------------------------------------------------------------------------------- |
| 47  | PSUITE-2-token-source-separation          | 2          | POST /access/v1/check/resource                                    | M2M identity ≠ Incoming-Token identity                                                             | TOKEN                           | **RLS row** with `condition` `subject.id == <fixed-end-user-sub>` (resolved via a TOKEN PIP on the `sub` claim); the policy does **not** match on the M2M account's `sub`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       | `true` when the Incoming-Token subject matches the fixed value, `false` when the M2M subject would have matched but the Incoming-Token does not — proves the thin client relays the end-user token and the server uses it for the RLS `condition`, not the M2M one                                                                                                                                                                                                                                                                                                                                                                                                                                                       | `golden/check-resource-v1/token-source-separation.json`                                                                                                                   | ------------------------------------------------------------------------------- |
| 48  | PSUITE-2-header-pip-prohibited            | 2          | POST /access/v1/check/resource                                    | Incoming-Token + custom-header map containing `tenant` and `authorization` passed to the Go helper | none                            | Reuses the ordinary OLS-allow fixture (`PARITY_CUSTOMER` / `READ`) so the request should succeed regardless of the caller-supplied prohibited headers                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           | The Go helper replicates the thin client's `HeadersFilter` behavior per **D-V** item 5 — it **strips** `authorization` and `tenant` (case-insensitive) from the caller-supplied header map before emitting the HTTP request. This row therefore tests the **Go helper's** transport behavior, not a server-side PIP property: if the helper leaked `authorization: bogus`, it would override the M2M bearer and the request would fail authentication instead of matching the baseline OLS-allow golden.                                                                                                                                                                                                                 | Same typed response as the baseline allow case; verify by a second sub-test that sends the same request with the prohibited headers absent and confirms the same decision | `golden/check-resource-v1/header-pip-prohibited/{stripped,manual-absent}.json`  |
| 49  | CLANG-string-equality                     | 2          | POST /access/v1/check/resource                                    | Incoming-Token non-anonymous                                                                       | none                            | **RLS row** with `condition` `resource.category == "PARITY_GOLD"`. Two sub-cases: resource with `category=PARITY_GOLD` (true) and resource with `category=PARITY_SILVER` (false). Exercises the string `==` operator on a literal RHS.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          | `true` / `false` matching the resource attribute                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | `golden/clang/string-equality.json`                                                                                                                                       | ------------------------------------------------------------------------------- |
| 50  | CLANG-number-relational                   | 2          | POST /access/v1/check/resource                                    | Incoming-Token non-anonymous                                                                       | none                            | **RLS row** with compound `condition` `resource.amount >= 100 AND resource.amount < 1000`. Three sub-cases with `amount` ∈ {50, 500, 1500} exercising below-bound / in-range / above-bound.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     | sub-cases: `false`, `true`, `false`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      | `golden/clang/number-relational.json`                                                                                                                                     | ------------------------------------------------------------------------------- |
| 51  | CLANG-boolean-and                         | 2          | POST /access/v1/check/resource                                    | Incoming-Token non-anonymous                                                                       | none                            | **RLS row** with `condition` `resource.active == true AND resource.verified == true`. Four sub-cases covering the Boolean `AND` truth table on `(active, verified)`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            | true/false/false/false across the 4 sub-cases                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            | `golden/clang/boolean-and.json`                                                                                                                                           | ------------------------------------------------------------------------------- |
| 52  | CLANG-boolean-or                          | 2          | POST /access/v1/check/resource                                    | Incoming-Token non-anonymous                                                                       | none                            | **RLS row** with `condition` `resource.priority == "HIGH" OR resource.escalated == true`. Four sub-cases covering the Boolean `OR` truth table on `(priority=HIGH?, escalated?)`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               | true/true/true/false across the 4 sub-cases                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              | `golden/clang/boolean-or.json`                                                                                                                                            | ------------------------------------------------------------------------------- |
| 53  | CLANG-not                                 | 2          | POST /access/v1/check/resource                                    | Incoming-Token non-anonymous                                                                       | none                            | **RLS row** with `condition` `NOT (resource.archived == true)`. Two sub-cases with `archived` ∈ {true, false}. Exercises `NOT` operator precedence and the `== true` on a Boolean attribute.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    | false/true                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               | `golden/clang/not.json`                                                                                                                                                   | ------------------------------------------------------------------------------- |
| 54  | CLANG-in-literal-collection               | 2          | POST /access/v1/check/resource                                    | Incoming-Token non-anonymous                                                                       | none                            | **RLS row** with `condition` `resource.status IN ("OPEN","PENDING","REVIEW")`. Four sub-cases: status=OPEN, status=PENDING, status=REVIEW, status=CLOSED. Exercises the literal-collection `IN` operator.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       | true/true/true/false                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     | `golden/clang/in-literal.json`                                                                                                                                            | ------------------------------------------------------------------------------- |
| 55  | CLANG-in-pip-collection                   | 2          | POST /access/v1/check/resource                                    | Incoming-Token non-anonymous                                                                       | GENERAL (list)                  | **RLS row** with `condition` `resource.status IN subject.parityStatusAllowed`. GENERAL-PIP returns a JSON array of status strings from `pip-mock`. Distinct from row 7 because the compared attribute is `resource.status` (a string) rather than `resource.id`, and the PIP delivers a **non-id** collection. Two sub-cases: mock returns `["OPEN","PENDING"]` → resource with status=OPEN is `true`; resource with status=CLOSED is `false`.                                                                                                                                                                                                                                                                                                                                                                                  | `true` / `false`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | `golden/clang/in-pip.json`                                                                                                                                                | ------------------------------------------------------------------------------- |
| 56  | CLANG-contains-any                        | 2          | POST /access/v1/check/resource                                    | Incoming-Token non-anonymous                                                                       | none                            | **RLS row** with `condition` `resource.tags CONTAINS ANY ("red","blue")`. Two sub-cases: resource with `tags=["red","green"]` (true) and `tags=["yellow","purple"]` (false). Exercises the `CONTAINS ANY` set-intersection operator on an array-valued resource attribute.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      | `true` / `false`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | `golden/clang/contains-any.json`                                                                                                                                          | ------------------------------------------------------------------------------- |
| 57  | CLANG-contains-all                        | 2          | POST /access/v1/check/resource                                    | Incoming-Token non-anonymous                                                                       | none                            | **RLS row** with `condition` `resource.tags CONTAINS ALL ("red","blue")`. Two sub-cases: resource with `tags=["red","blue","green"]` (true) and `tags=["red","green"]` (false). Exercises the `CONTAINS ALL` set-containment operator and distinguishes it from `CONTAINS ANY` in row 56.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       | `true` / `false`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | `golden/clang/contains-all.json`                                                                                                                                          | ------------------------------------------------------------------------------- |
| 58  | CLANG-null-handling                       | 2          | POST /access/v1/check/resource                                    | Incoming-Token non-anonymous                                                                       | none                            | **RLS row** with `condition` `resource.ownerId != null`. Two sub-cases: resource with `ownerId=42` (true) and `ownerId` field omitted (false). Exercises the engine's null-handling semantics — whether an absent field deserializes to null and whether `!= null` is accepted. The legacy operator keyword (`!= null` vs. `IS NOT NULL` vs. `isNotNull()`) is a Phase 1 inventory item (OQ-SUITE-6).                                                                                                                                                                                                                                                                                                                                                                                                                           | `true` / `false`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | `golden/clang/null.json`                                                                                                                                                  | ------------------------------------------------------------------------------- |
| 59  | CLANG-nested-subject-access               | 2          | POST /access/v1/check/resource                                    | Incoming-Token non-anonymous                                                                       | GENERAL (dict)                  | **RLS row** with `condition` `resource.department == subject.parityMetaDepartment`. Reuses the dict-returning GENERAL-PIP family from row 9, but exercises a single extracted leaf alias in isolation. Two sub-cases: mock returns `{"department":"SALES"}`, resource has `department=SALES` (true); mock returns the same dict, resource has `department=ENGINEERING` (false).                                                                                                                                                                                                                                                                                                                                                                                                                                                 | `true` / `false`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | `golden/clang/nested-subject.json`                                                                                                                                        | ------------------------------------------------------------------------------- |
| 60  | CLANG-filter-rsql-compound                | 6          | POST /access/v1/check/filter                                      | Incoming-Token non-anonymous                                                                       | none                            | **RLS row** with compound `rsqlPredicate` template `amount=lt=1000;status=in=(OPEN,PENDING)`. Exercises RSQL `;` (AND) combination, `=lt=` comparison, and `=in=` collection membership inside a single predicate template. Golden captures the rendered predicate string verbatim.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             | `OldFilterEvaluationResult` with `calculationResult=USE_FILTER_CONDITION` (or `ALLOW` — captured from the real server) and the compound RSQL string in `rsqlFilterCondition`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             | `golden/clang/filter-rsql-compound.json`                                                                                                                                  | ------------------------------------------------------------------------------- |
| 61  | AGG-multi-role-allow                      | 2          | POST /access/v1/check/resource                                    | Incoming-Token non-anonymous                                                                       | none                            | Two pure-OLS rows for `PARITY_CUSTOMER READ`: row A keyed on `ROLE_PARITY_READER`, row B keyed on `ROLE_PARITY_REVIEWER`. End-user token carries **only** `ROLE_PARITY_REVIEWER`. Proves that OLS-row matching is a per-role OR across all rows — any single matching role is sufficient.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       | `true`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   | `golden/agg/multi-role-allow.json`                                                                                                                                        | ------------------------------------------------------------------------------- |
| 62  | AGG-multi-role-deny                       | 2          | POST /access/v1/check/resource                                    | Incoming-Token non-anonymous                                                                       | none                            | Same two-row setup as row 61; end-user token carries `ROLE_PARITY_OTHER` (neither of the two policy roles). Proves the negative of row 61.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      | `false`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  | `golden/agg/multi-role-deny.json`                                                                                                                                         | ------------------------------------------------------------------------------- |
| 63  | AGG-predicate-union-two-rows              | 6          | POST /access/v1/check/filter                                      | Incoming-Token non-anonymous                                                                       | none                            | Two RLS rows for the same `(PARITY_ORDER, LIST, ROLE_PARITY_READER)`: row A with `rsqlPredicate` `ownerId==${subject.id}`, row B with `rsqlPredicate` `status==PUBLIC`. User carries `ROLE_PARITY_READER`. Per ADR-0025 / 20260326-rls-predicate-or-aggregation-task.md the Authz Agent side aggregates as `(ownerId==X),(status==PUBLIC)`; this row asserts the legacy `access-control` engine emits the **same** deserialized string so parity holds.                                                                                                                                                                                                                                                                                                                                                                         | `OldFilterEvaluationResult` with `calculationResult=USE_FILTER_CONDITION` (or whatever the legacy server emits — captured from the real server in record mode) and a `rsqlFilterCondition` containing **both** sub-predicates OR-joined per ADR-0025                                                                                                                                                                                                                                                                                                                                                                                                                                                                     | `golden/agg/predicate-union-two-rows.json`                                                                                                                                | ------------------------------------------------------------------------------- |
| 64  | AGG-ols-row-plus-rls-row                  | 6          | POST /access/v1/check/filter                                      | Incoming-Token non-anonymous                                                                       | none                            | Two rows for the same `(PARITY_ORDER, LIST, ROLE_PARITY_READER)`: row A is pure OLS (`roles + resourceType + operation` only, no `condition`, no predicate — normalized to `condition: true` by the legacy loader per policy-format.md §Loader Normalization), row B has a restrictive `rsqlPredicate` `ownerId==${subject.id}`. Legacy semantics expected: row A alone would grant access with no filter, so the superset-wins OR-aggregation yields "allow all"; row B's restrictive predicate is absorbed. Neither row uses a wildcard role — both are scoped to the same `ROLE_PARITY_READER` — so this row exercises the pure OLS-vs-RLS combining case without depending on the (non-existent per D-S) legacy wildcard-role support. OQ-SUITE-8 tracks the exact wire shape the legacy engine emits for this combination. | `OldFilterEvaluationResult` per legacy server — captured in record mode                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  | `golden/agg/ols-plus-rls.json`                                                                                                                                            | ------------------------------------------------------------------------------- |
| 65  | AGG-condition-or-across-rows              | 2          | POST /access/v1/check/resource                                    | Incoming-Token non-anonymous                                                                       | none                            | Two RLS rows for the same `(PARITY_CUSTOMER, READ, ROLE_PARITY_READER)` with **different** `condition` ASTs: row A `resource.tier == "GOLD"`, row B `resource.tier == "SILVER"`. Three sub-cases: resource tier ∈ {GOLD, SILVER, BRONZE}. Proves that `condition`-level OR-aggregation across matching rows is symmetric with predicate OR-aggregation in row 63 — any row's `condition` evaluating to `true` is sufficient for an allow.                                                                                                                                                                                                                                                                                                                                                                                       | true / true / false                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      | `golden/agg/condition-or-across-rows.json`                                                                                                                                | ------------------------------------------------------------------------------- |
| 66  | AGG-bulk-per-id                           | 3          | POST /access/v1/check/resource/bulk                               | Incoming-Token non-anonymous                                                                       | none                            | Bulk request with four resources, each carrying a different `tier` attribute ∈ {GOLD, SILVER, BRONZE, PLATINUM}. Two RLS-condition rows (same `(PARITY_CUSTOMER, READ, ROLE_PARITY_READER)` tuple) — row A `tier == "GOLD"`, row B `tier == "SILVER"`. Proves that per-id aggregation on the bulk endpoint respects the row 65 OR semantics independently for each id.                                                                                                                                                                                                                                                                                                                                                                                                                                                          | `Set<String>` containing the two ids whose tier ∈ {GOLD, SILVER}                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | `golden/agg/bulk-per-id.json`                                                                                                                                             | ------------------------------------------------------------------------------- |
| 67  | AGG-per-operation-different-rules         | 4          | POST /access/v1/check/resource/bulk/operations                    | Incoming-Token non-anonymous                                                                       | none                            | Two operations, `READ` and `WRITE`, over three resources. Policy rows: `(PARITY_CUSTOMER, READ, ROLE_PARITY_READER)` with `rsqlPredicate` `status==PUBLIC`, and **no** row for `(PARITY_CUSTOMER, WRITE, ROLE_PARITY_READER)`. Proves the per-operation key independence of the `Map<String, Set<String>>` return shape: `READ` yields the ids that match the predicate, `WRITE` yields an empty array (or is absent from the map — captured from the real server).                                                                                                                                                                                                                                                                                                                                                             | `Map<String, Set<String>>` with `READ` populated and `WRITE` empty/absent                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                | `golden/agg/per-operation.json`                                                                                                                                           | ------------------------------------------------------------------------------- |
| 68  | SUB-general-scalar-string                 | 6          | POST /access/v1/check/filter                                      | Incoming-Token non-anonymous                                                                       | GENERAL (scalar string)         | **RLS row** with `rsqlPredicate` template `status==${subject.parityStatusScalar}`. GENERAL-PIP `subject.parityStatusScalar` is declared with `pipType=GENERAL`, `httpMethod=POST`, `url=http://pip-mock:8090/api/v1/pip/scalar-string`; mock returns a **scalar string** body `"OPEN"` (not an array, not an object). The legacy engine substitutes the literal value into the placeholder, producing the rendered RSQL string `status==OPEN` (or `status=="OPEN"` — quoting captured from the real server). Proves that GENERAL PIPs returning a leaf string survive template substitution into a predicate.                                                                                                                                                                                                                   | `OldFilterEvaluationResult` whose `rsqlFilterCondition` contains the rendered string with the mock value substituted in place                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            | `golden/sub/general-scalar-string.json`                                                                                                                                   | ------------------------------------------------------------------------------- |
| 69  | SUB-general-scalar-number                 | 6          | POST /access/v1/check/filter                                      | Incoming-Token non-anonymous                                                                       | GENERAL (scalar number)         | **RLS row** with `rsqlPredicate` template `amount=lt=${subject.parityMaxAmountScalar}`. GENERAL-PIP returns a **scalar JSON number** `1000` from `pip-mock`. Proves that the substitution preserves the numeric type — the rendered predicate is `amount=lt=1000`, not `amount=lt="1000"`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      | `OldFilterEvaluationResult` with the rendered numeric predicate, no quoting around the substituted value                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 | `golden/sub/general-scalar-number.json`                                                                                                                                   | ------------------------------------------------------------------------------- |
| 70  | SUB-general-scalar-boolean                | 6          | POST /access/v1/check/filter                                      | Incoming-Token non-anonymous                                                                       | GENERAL (scalar boolean)        | **RLS row** with `rsqlPredicate` template `archived==${subject.parityArchivedScalar}`. GENERAL-PIP returns a **scalar JSON boolean** `false` from `pip-mock`. Proves the Boolean-scalar substitution path; rendered predicate is `archived==false`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             | `OldFilterEvaluationResult` with the rendered Boolean predicate (lowercase `false` — captured from the real server)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      | `golden/sub/general-scalar-boolean.json`                                                                                                                                  | ------------------------------------------------------------------------------- |
| 71  | SUB-token-scalar-into-sql                 | 6          | POST /access/v1/check/filter                                      | Incoming-Token non-anonymous                                                                       | TOKEN                           | **RLS row** with `sqlFilterCondition` template `department = '${subject.parityDepartment}'`. The TOKEN-PIP `subject.parityDepartment` is the same scalar binding as row 5 (JWT `department` claim). Proves template substitution works on the `sqlFilterCondition` field — not just `rsqlPredicate`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            | `OldFilterEvaluationResult` whose `sqlFilterCondition` is the rendered SQL string with the JWT claim value substituted into the SQL literal                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              | `golden/sub/token-scalar-into-sql.json`                                                                                                                                   | ------------------------------------------------------------------------------- |
| 72  | SUB-header-scalar-into-mongodb            | 6          | POST /access/v1/check/filter                                      | Incoming-Token + custom header `x-parity-pip-attribute`                                            | HEADER                          | **RLS row** with `mongodbFilterCondition` template `{"region": "${subject.parityHeaderAttr}"}`. The HEADER-PIP binding is the same as row 6. Proves template substitution works on the `mongodbFilterCondition` field — including substitution inside a JSON-object string.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     | `OldFilterEvaluationResult` whose `mongodbFilterCondition` is the rendered Mongo query string with the header value substituted in place                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 | `golden/sub/header-scalar-into-mongodb.json`                                                                                                                              | ------------------------------------------------------------------------------- |
| 73  | SUB-general-array-into-sql                | 6          | POST /access/v1/check/filter                                      | Incoming-Token non-anonymous                                                                       | GENERAL (list return)           | **RLS row** with `sqlFilterCondition` template `id IN (${subject.parityAllowed})` — same array PIP as row 7 but consumed through the `sqlFilterCondition` field rather than `rsqlPredicate`. Proves the array-to-comma-list expansion is symmetric across predicate types — the legacy engine expands `${subject.parityAllowed}` to `1,2,3` (or `'1','2','3'` — quoting captured from the real server) regardless of the surrounding template.                                                                                                                                                                                                                                                                                                                                                                                  | `OldFilterEvaluationResult` whose `sqlFilterCondition` contains the comma-joined id list rendered into the SQL `IN (...)` clause                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | `golden/sub/general-array-into-sql.json`                                                                                                                                  | ------------------------------------------------------------------------------- |
| 74  | SUB-multi-pip-one-template                | 6          | POST /access/v1/check/filter                                      | Incoming-Token non-anonymous                                                                       | TOKEN + GENERAL (scalar number) | **RLS row** with `rsqlPredicate` template combining **two** PIP placeholders in a single string: `tier==${subject.parityDepartment};amount=lt=${subject.parityMaxAmountScalar}`. The TOKEN PIP and the GENERAL scalar-number PIP from rows 71 and 69 are both referenced. Proves the substitution engine handles multiple placeholders per template, in order, without bleeding values across slots.                                                                                                                                                                                                                                                                                                                                                                                                                            | `OldFilterEvaluationResult` whose `rsqlFilterCondition` has both placeholders rendered with their respective PIP values in the correct positions                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | `golden/sub/multi-pip-one-template.json`                                                                                                                                  | ------------------------------------------------------------------------------- |
| 75  | SUB-general-scalar-special-chars          | 6          | POST /access/v1/check/filter                                      | Incoming-Token non-anonymous                                                                       | GENERAL (scalar string)         | **RLS row** with `rsqlPredicate` template `tag==${subject.parityTagScalar}`. GENERAL-PIP returns a string with characters that have meaning inside RSQL (`,`, `;`, `(`, `)`, `'`, `"`) — for example `"red,blue;green"`. Captures whichever escaping / quoting the legacy engine applies (or whether it skips/rejects the substitution); golden is recorded verbatim. **Phase 1 inventory item OQ-SUITE-9** must determine the legacy escaping rules from `sample-sources/access-control/` source before this fixture is finalized — the seed PUT may otherwise be rejected with HTTP 400. If Authz Agent's predicate emitter does not produce a deserialized-equal rendering for special characters, an ADR-backed deviation is required before Step 4 close.                                                                  | `OldFilterEvaluationResult` per legacy server — captured in record mode                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  | `golden/sub/general-scalar-special-chars.json`                                                                                                                            | ------------------------------------------------------------------------------- |
| 76  | ENT-contains                              | 2          | POST /access/v1/check/resource                                    | Incoming-Token non-anonymous                                                                       | ENTITLEMENT (mocked EA)         | **RLS row** with `condition` `subject.entitledResources.of('PARITY_CONTRACT').as('Owner') CONTAINS resource.id`. The `entitlements-mock` (D-U) is pinned in `SetupTest` to return `{"PARITY_CONTRACT": {"Owner": ["id-1"]}}` for `parity-reader`'s userId on the V3 endpoint per usage docs. Two sub-cases: `resource.id=id-1` (true), `resource.id=id-2` (false). Exercises the basic `CONTAINS` operator and the V3 `GetDirectUserEntitlementsResponse` parse path on legacy AC.                                                                                                                                                                                                                                                                                                                                              | `true` / `false` per sub-case                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            | `golden/ent/contains.json`                                                                                                                                                | ------------------------------------------------------------------------------- |
| 77  | ENT-in-rhs                                | 2          | POST /access/v1/check/resource                                    | Incoming-Token non-anonymous                                                                       | ENTITLEMENT (mocked EA)         | **RLS row** with `condition` `resource.id IN subject.entitledResources.of('PARITY_CONTRACT').as('Owner')` — same semantic as row 76 but with the operands flipped (RHS is the entitlement-derived set). Same mock pin. Two sub-cases mirror row 76. Proves the engine treats `IN`/`CONTAINS` symmetrically for entitlements.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    | `true` / `false` per sub-case                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            | `golden/ent/in-rhs.json`                                                                                                                                                  | ------------------------------------------------------------------------------- |
| 78  | ENT-multi-entitlement-as                  | 2          | POST /access/v1/check/resource                                    | Incoming-Token non-anonymous                                                                       | ENTITLEMENT (mocked EA)         | **RLS row** with `condition` `subject.entitledResources.of('PARITY_CONTRACT').as('Owner', 'Accountant') CONTAINS resource.id`. Mock returns `{"PARITY_CONTRACT": {"Owner": ["id-1"], "Accountant": ["id-2"]}}`. Three sub-cases: `id-1` (true via Owner), `id-2` (true via Accountant), `id-3` (false). Exercises the multi-entitlement `as(...)` list and the union semantics across multiple entitlement names per docs row 22.                                                                                                                                                                                                                                                                                                                                                                                               | true / true / false                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      | `golden/ent/multi-entitlement-as.json`                                                                                                                                    | ------------------------------------------------------------------------------- |
| 79  | ENT-contains-any                          | 2          | POST /access/v1/check/resource                                    | Incoming-Token non-anonymous                                                                       | ENTITLEMENT (mocked EA)         | **RLS row** with `condition` `subject.entitledResources.of('PARITY_CONTRACT').as('Owner') CONTAINS ANY resource.relatedIds`. Mock returns `{"PARITY_CONTRACT": {"Owner": ["id-1", "id-2"]}}`. Resource has `relatedIds=["id-1", "id-99"]` — true (intersection non-empty). Negative sub-case: `relatedIds=["id-99"]` — false (empty intersection). Exercises the `CONTAINS ANY` set-intersection operator distinct from row 76's element-membership `CONTAINS`.                                                                                                                                                                                                                                                                                                                                                                 | `true` / `false` per sub-case                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            | `golden/ent/contains-any.json`                                                                                                                                            | ------------------------------------------------------------------------------- |
| 80  | ENT-is-empty                              | 2          | POST /access/v1/check/resource                                    | Incoming-Token non-anonymous                                                                       | ENTITLEMENT (mocked EA)         | **RLS row** with `condition` `subject.entitledResources.of('PARITY_CONTRACT').as('Owner') IS EMPTY`. Two sub-cases: (a) mock pinned to return `{"PARITY_CONTRACT": {"Owner": []}}` — true (Owner set is empty); (b) mock pinned to return `{"PARITY_CONTRACT": {"Owner": ["id-1"]}}` — false. Exercises `IS EMPTY` and ensures the legacy engine reads an absent or empty entitlement set as empty without throwing.                                                                                                                                                                                                                                                                                                                                                                                                            | `true` / `false` per sub-case                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            | `golden/ent/is-empty.json`                                                                                                                                                | ------------------------------------------------------------------------------- |
| 81  | ENT-not-contains                          | 2          | POST /access/v1/check/resource                                    | Incoming-Token non-anonymous                                                                       | ENTITLEMENT (mocked EA)         | **RLS row** with `condition` `subject.entitledResources.of('PARITY_CONTRACT').as('Owner') NOT CONTAINS resource.id` (or `NOT IN` — Phase 1 verifies the spelling per the AST grammar). Same mock as row 76; two sub-cases assert the negation symmetry of `CONTAINS`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           | `false` / `true` per sub-case                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            | `golden/ent/not-contains.json`                                                                                                                                            | ------------------------------------------------------------------------------- |
| 82  | ENT-multi-resource-type                   | 2          | POST /access/v1/check/resource                                    | Incoming-Token non-anonymous                                                                       | ENTITLEMENT (mocked EA)         | **RLS row** with `condition` `subject.entitledResources.of('PARITY_CONTRACT').as('Owner') CONTAINS resource.id`. Mock returns a multi-resourceType payload `{"PARITY_CONTRACT": {"Owner": ["id-1"]}, "PARITY_ACCOUNT": {"Owner": ["id-2"]}}`. Two sub-cases: resource type `PARITY_CONTRACT` id `id-1` (true), `PARITY_CONTRACT` id `id-2` (false — `id-2` is in PARITY_ACCOUNT, not PARITY_CONTRACT). Proves the `of(<resourceType>)` selector reads the correct outer-key bucket and does not leak between resource types.                                                                                                                                                                                                                                                                                                    | `true` / `false` per sub-case                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            | `golden/ent/multi-resource-type.json`                                                                                                                                     | ------------------------------------------------------------------------------- |
| 83  | ENT-empty-user                            | 2          | POST /access/v1/check/resource                                    | Incoming-Token non-anonymous                                                                       | ENTITLEMENT (mocked EA)         | **RLS row** with `condition` `subject.entitledResources.of('PARITY_CONTRACT').as('Owner') CONTAINS resource.id`. Mock returns an **empty** body `{}` — the user has no entitlements at all. Two sub-cases: any resource id → false (no entitlements to match); same condition flipped to `IS EMPTY` → true. Proves the legacy engine handles the all-empty-user case without throwing and that `IS EMPTY` correctly reports true on a missing `of(...)` bucket.                                                                                                                                                                                                                                                                                                                                                                 | `false` / `true` per sub-case                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            | `golden/ent/empty-user.json`                                                                                                                                              | ------------------------------------------------------------------------------- |

**Count:** 83 **rows** total — 80 golden-asserted rows + 3
exception-asserted rows (validation fixtures, rows 11, 16, 29). Per
**D-X** (iteration 8) each multi-sub-case row maps to multiple testify
subtests via `s.Run`, each with its own committed golden file; the
expected total **golden file count is ~120** (rows with 2–4 sub-cases
×80 golden-asserted rows — executor confirms exact number in Phase 7
Execution Report). The `Parity suite passed: 130/130 cases green.` line
reports **leaf sub-case** count, not golden file count. The four wildcard-role rows that previous
iterations named PSUITE-2-wildcard / PSUITE-4-wildcard /
PSUITE-6-wildcard / AGG-wildcard-wins-over-predicate were **removed in
iteration 5 per D-S** after Phase 1 reading confirmed legacy AC's
simplified-policy format has no role-level wildcard construct — see
the D-S entry for the code-level evidence. The 8 new ENT-\* rows
(rows 76–83) were added in **iteration 6 per D-U** to cover the
entitlements PIP category against a mocked `entitlements-aggregator`
service. The final row count goes into the parent plan update as
`130/130 cases green`; if Phase 1 surfaces additional language features,
aggregation variants, or entitlement operators reachable through the
unmodified thin client, the count grows before the execution report is
filled.

**Coverage cross-check against parity contract §PIP Observability Note:**

1. TOKEN-PIP-driven RLS rows (`condition` or predicate template
   references a PIP attribute bound to a JWT claim): rows 5, 25, 43, 47.
   Rows 25 and 43 hit the RLS surface through a filter endpoint (Boolean
   → predicate bundle), rows 5 and 47 hit the same RLS rule through
   `check/resource` (reduced to Boolean); both surfaces must produce
   parity-equal results on the same fixture. Item 1 of the parity
   contract's PIP Observability Note ("one TOKEN-PIP-driven RLS scenario
   behind every filter endpoint") is met by rows 25 and 43.
2. HEADER-PIP-driven RLS rows (`condition` or predicate template
   references a PIP attribute bound to a custom header): rows 6, 26, 44,
   48. Row 48 additionally covers the prohibited-header strip
   (`HeadersFilter` silently drops `tenant`/`authorization`, so the
   attribute is absent at evaluation time). Item 2 of the PIP note is
   met by rows 26 and 44.
3. GENERAL-PIP-driven RLS rows with **array-returning** PIP
   (`subject.<alias>` is a JSON array): rows 7, 8, 14, 27, 33, 45 —
   covering `check/resource` (rows 7/8), bulk (row 14), v1 filter
   predicate (row 27), v2 `check/resource` (row 33), and v2 filter
   predicate (row 45).
4. GENERAL-PIP-driven RLS rows with **dict-returning** PIP
   (`subject.<alias>` is a JSON object, the `condition`/predicate reads
   nested fields `subject.<alias>.<field>`): rows 9, 10, 15, 28, 34, 46
   — mirroring item 3 across the same endpoint set. Item 3 of the PIP
   note ("one GENERAL-PIP-driven RLS scenario against the mandatory
   mock PIP service") is exceeded on purpose: the suite covers both
   return-shape families because the legacy PIP runtime stores the
   deserialized body under `subject.<alias>` verbatim and the
   condition-AST walks whatever shape it gets, so array access and
   nested-field access are two distinct code paths.
5. `Incoming-Token` non-anonymous scenario per implemented endpoint →
   at least one row per `#` of the parity contract. Every row in
   PSUITE blocks that is **not** in the anonymous list of item 6 below,
   plus every row in CLANG / AGG / SUB blocks (49–75), qualifies.
6. `Authorization-Type: anonymous` scenario per implemented endpoint →
   rows 4, 13, 18, 20, 24, 32, 36, 38, 42 — at least one per `#` of the
   parity contract. Endpoint 1 (`/api-version`) is M2M-only by
   construction and is therefore exempt; that is consistent with the
   parity contract §2.2 M2M convention.
7. Validation fixtures (all three are now server-side per the **D-A** /
   **D-V** Go pivot): row 11 (v1 check/resource missing `operation` —
   HTTP 400 `{"message": "...'operation' field is required"}`), row 16
   (v1 check/resource/bulk duplicate ids — HTTP 400 with `duplicated
   ids` substring), row 29 (v1 check/filter missing `resourceType` —
   HTTP 400 with `resourceType` substring). The Go suite reaches all
   three server-side validation paths directly because there is no
   client-side pre-validator to short-circuit them — strictly better
   coverage than the iteration-1 Java-thin-client framing had. Other
   server-side validation shapes from `AccessControlExceptionControllerAdvice`
   (missing `type`, missing `id`, malformed JSON body, etc.) are
   reachable in principle from Go but are out of scope for Step 3 —
   executor can add them as follow-up rows if Phase 1 surfaces them
   as parity-relevant, with owner approval per **D-W**.
8. Condition language coverage (CLANG-\*) → rows 49–60. Each row
   isolates one operator or language feature (string `==`, compound
   numeric relational, Boolean `AND`/`OR`/`NOT`, `IN` against literal
   vs. PIP-backed collections, `CONTAINS ANY`/`CONTAINS ALL`, `null`
   handling, nested subject-field access, compound RSQL) with explicit
   sub-cases that cross the truth boundary of the operator. Together
   they prove the condition-language parser and evaluator on both
   sides of the parity boundary agree.
9. Policy combining / aggregation coverage (AGG-\*) → rows 61–67. Each
   row seeds **≥2 policy rows** on the same `(resourceType, operation)`
   locator and asserts the legacy engine's aggregation shape on both
   `check/resource` (Boolean collapse) and `check/filter` (materialized
   predicate bundle). The expected shape for predicate OR-aggregation
   is defined on the Authz Agent side by [ADR-0025](../../decisions) via
   20260326-rls-predicate-or-aggregation-task.md
   — row 63 asserts the legacy baseline matches that shape, and row 64
   is a Phase 1 inventory item because the exact OLS-row-vs-RLS-row
   combining precedence is not yet documented in a parity-contract
   decision (OQ-SUITE-8). Wildcard-role combining is **not** covered —
   per D-S the legacy simplified-policy format has no role-level
   wildcard construct, so there is no wildcard-vs-predicate aggregation
   case to capture against the legacy reference.
10. Predicate template substitution coverage (SUB-\*) → rows 68–75. Each
    row seeds an RLS policy with a `${subject.<alias>}` placeholder
    inside one of three predicate-string fields (`rsqlPredicate`,
    `sqlFilterCondition`, `mongodbFilterCondition`;
    `customFilterCondition` excluded per **D-P**) and asserts the
    **rendered** wire shape after the legacy engine substitutes the
    PIP value in. Coverage matrix:
    1. Scalar **string** GENERAL PIP → `rsqlPredicate` (row 68).
    2. Scalar **number** GENERAL PIP → `rsqlPredicate` (row 69).
    3. Scalar **boolean** GENERAL PIP → `rsqlPredicate` (row 70).
    4. Scalar **string** TOKEN PIP → `sqlFilterCondition` (row 71).
    5. Scalar **string** HEADER PIP → `mongodbFilterCondition` (row 72).
    6. **Array** GENERAL PIP → `sqlFilterCondition` (row 73 — array-
       into-non-RSQL cross-product, complementing rows 7/27 which use
       RSQL).
    7. **Two** PIPs in one template (TOKEN scalar + GENERAL scalar
       number) → `rsqlPredicate` (row 74).
    8. **Special characters** in a scalar GENERAL PIP value (row 75,
       Phase 1 inventory item OQ-SUITE-9 for escaping rules).
    Together they prove that PIP-value-into-predicate-string
    substitution works for every leaf type the GENERAL PIP runtime can
    deserialize (string / number / Boolean / array), for two of the
    three non-RSQL predicate types in addition to RSQL, and for
    multi-placeholder templates. Per **D-T** server-side substitution
    in the legacy engine is locked as the parity premise; Step 4 must
    reproduce these rendered strings deserialized-equal from Authz
    Agent's predicate emitter — if any divergence surfaces, it is a
    Step 4 code-fix on the Authz Agent side.
11. Entitlements coverage (ENT-\*) → rows 76–83. Each row seeds an RLS
    policy whose `condition` walks the
    `subject.entitledResources.of(...).as(...)` AST against a
    deterministic `entitlements-mock` response (per **D-U** — the mock
    is the same `pip-stub:local` binary on a separate DNS alias,
    controlled via the same `POST /__mock__/responses` surface as
    `pip-mock`). Coverage:
    1. `CONTAINS` / `IN` operator forms (rows 76, 77).
    2. Multi-entitlement `as(...)` union (row 78).
    3. `CONTAINS ANY` set-intersection (row 79).
    4. `IS EMPTY` (row 80).
    5. `NOT CONTAINS` negation (row 81).
    6. Multi-resourceType disambiguation via `of(<resourceType>)`
       (row 82).
    7. All-empty-user fallback (row 83).
    Step 4 must produce deserialized-equal Boolean decisions from
    Authz Agent's entitlements PIP runtime against the same mock; if
    Authz Agent does not implement an `entitlements-aggregator`-equivalent
    PIP at all, every ENT row is a Step 4 implementation gate and must
    be either coded or filed as an ADR-backed deviation before Step 4
    closes (no silent skip). The aggregator itself is not run by the
    parity stack — only its HTTP wire shape, served by the mock per
    **D-U**.

## Open Questions

Phase 1 of this handover is expected to surface a small number of runtime
questions. They live here until the executor can resolve them against
`sample-sources/` or escalate them to the parent plan owner. Use placeholder
`OQ-SUITE-N` ids to avoid collisions with the parity contract's Q-numbering.

1. **OQ-SUITE-1** — *Resolved by D-N*. Phase 3 additively extends
   `parity-realm.json` with the `parity-reader` / `parity-reviewer` /
   `parity-multi-role` / `parity-other` / `parity-anon-baseline` users and
   the `parity-end-user` password-grant client; the claim set is widened
   additively to include at least `department` and `tier` per row needs.
   Phase 1 still verifies the exact claim emitter path in the Netcracker
   identity-provider fork before committing the realm edit — if a claim
   needs a custom protocol mapper rather than a plain user-attribute
   mapping, that mapper is added to the realm file in the same commit.
2. **OQ-SUITE-2** — *Resolved by D-N*. Phase 3 adds a
   `directAccessGrantsEnabled=true` client named `parity-end-user` in
   `parity-realm.json` (same file, not `cloud-common-realm.json`) so
   `ParityTokenFactory.endUserToken(username)` can obtain tokens via the
   Resource-Owner-Password-Credentials grant. The existing `parity-m2m`
   M2M client is left unchanged.
3. **OQ-SUITE-3** — *Partially resolved by D-N*. Every seeded test user's
   password must satisfy the legacy `DEFAULT_PASSWORD_POLICY` (length ≥ 8,
   one digit, one upper, one lower, one special — same constraints Step 2
   Follow-up 1.8 hit for the admin bootstrap). Phase 1 still needs to
   verify the policy does not additionally require rotation after first
   login for non-admin users; if it does, the realm seed sets
   `requiredActions=[]` on each user to skip the rotation prompt.
4. **OQ-SUITE-4** — *Closed by D-S (owner iteration 5).* Phase 1 reading
   of BaseSimplifiedPolicy.java:27,
   SimplifiedPolicyMappingService.java:225-232,
   and policy-wildcards/README.md
   confirmed that legacy `access-control` simplified-policy format has
   **no** role-level wildcard construct: `roles: ["*"]` is rendered
   literally into the rule target `subject.roles CONTAINS ANY '*'`
   which matches only a user with the literal string role `*` (nobody
   has it). The only "wildcard-ish" feature is the global-access-policy
   pattern (component=ALL + resourceType=ALL + operation=ALL), which
   still requires an explicit role list and is a
   resource/operation-level wildcard, not a role-level one. Rows
   previously numbered 5 / 20 / 31 / 67 (PSUITE-2-wildcard /
   PSUITE-4-wildcard / PSUITE-6-wildcard / AGG-wildcard-wins-over-predicate)
   have been removed from the catalogue. Wildcard fast-path coverage
   lives in Authz Agent's own integration suite at
   `tests/integration/testify/wildcard_access_test.go` — parity is
   **not** a valid framing for it because there is no legacy
   counterpart.
5. **OQ-SUITE-5** — *Closed by D-R (owner iteration 5).* Every
   `run-parity-suite.sh` invocation issues a clean seed before the
   Go test run starts — wipe the `PARITY` domain via the legacy
   simplified-policy delete path (or an empty-body PUT which
   `SimplifiedPolicyMappingService.updateSimplifiedConfiguration:80`
   treats as a full delete), then re-PUT the full fixture pack.
   Deterministic at the cost of ~10–30s per re-run; developer
   iteration on fixture JSON takes effect without needing
   `docker compose down -v`. Step 2 `smoke.sh` is unchanged and still
   relies on whatever `ac-seed` left on first boot — the wipe
   operation targets only the `PARITY` domain, never the global state.
6. **OQ-SUITE-6** — What is the exact operator / keyword spelling the
   legacy simplified-policy `condition` AST accepts for each of the
   language features covered by the CLANG block (rows 49–60)? Specifically:
   `==` vs. `=`, `!=` vs. `<>`, `AND`/`OR`/`NOT` case-sensitivity,
   `IN (v1,v2,v3)` vs. `IN [v1,v2,v3]` vs. `IN(v1,v2,v3)`, `CONTAINS ANY`
   vs. `containsAny(...)`, `null` literal vs. `IS NULL` / `IS NOT NULL`,
   nested field access `subject.meta.field` vs. `subject['meta']['field']`.
   Phase 1 must grep `sample-sources/access-control/` (start from
   `PolicyConditionEvaluator`, `ConditionParser`,
   `SimplifiedConditionEvaluator`, or an equivalent symbol — name discovered
   at read-time) to produce a reference sheet of accepted spellings before
   Phase 3 writes any CLANG fixture. Any fixture that uses an unaccepted
   spelling is rejected at `PUT /access/v1/simplifiedPolicies/` seed time
   with HTTP 400 and blocks the suite, so this inventory must land before
   the seed extension.
7. **OQ-SUITE-7** — *Closed by D-S (owner iteration 5).* The question
   was about wildcard-row-vs-restrictive-predicate-row aggregation
   precedence on `check/filter`. Since D-S removed wildcard rows from
   the catalogue (legacy simplified-policy format has no role-level
   wildcard construct), the combining case this OQ tracked no longer
   exists in the suite. The related pure-OLS-row-vs-RLS-row combining
   case survives as row 64 (AGG-ols-row-plus-rls-row) and is tracked
   separately by OQ-SUITE-8.
8. **OQ-SUITE-8** — For the pure OLS row + RLS row combination (row 64)
   where neither row uses a wildcard role —
   both are scoped to the same `ROLE_PARITY_READER`. Row A is normalized
   to `condition: true` by the loader (per
   ../policy-format.md §Loader Normalization items
   81–82) and has no predicate; row B has a restrictive `rsqlPredicate`.
   What does the legacy server emit? The expected answer from the
   simplified-format semantics is "row A alone already unconditionally
   allows, so the predicate union collapses to allow-all", but the exact
   `FilterResponse` shape must be captured from the real server. If
   Authz Agent's rls.rego does not already produce the same shape, this
   is the second ADR-backed deviation candidate.
9. **OQ-SUITE-9** — What are the legacy `access-control` template-
   substitution / escaping rules for rendering PIP values into the
   predicate string fields used by the SUB block (rows 68–75)? Specifically:
   1. How are scalar **strings** quoted on substitution? `${subject.x}` →
      `value` (no quotes, raw), `'value'` (single-quoted), `"value"`
      (double-quoted), or context-dependent on the surrounding predicate
      type (RSQL vs SQL vs Mongo)?
   2. How are scalar **numbers** rendered — as raw integer, as
      `"<digits>"`, or coerced based on the operator (`=lt=` numeric vs
      `==` string)?
   3. How are scalar **Booleans** rendered — `true`/`false`, `True`/`False`,
      `1`/`0`?
   4. How are **arrays** expanded inside non-RSQL templates (`sqlFilterCondition`,
      `mongodbFilterCondition`)? RSQL is documented as comma-list inside
      `=in=(...)`; SQL would naturally take comma-list inside `IN (...)`,
      but the engine may or may not auto-quote each element.
   5. How are **special characters** in a scalar string handled — escaped
      with backslash, escaped via doubling (`'` → `''`), URL-encoded,
      passed through verbatim (and accepted by the RSQL parser only if the
      caller already escaped them), or rejected at seed time with HTTP 400?
   6. What happens when a template references `${subject.<alias>}` and the
      PIP returns **null** or an empty body — the whole predicate field
      drops to `null`, an empty string is substituted, the entire row is
      dropped from aggregation, or an exception is thrown server-side?
   Phase 1 must grep `sample-sources/access-control/` (likely starting
   from `SimplifiedPolicyRenderer`, `PredicateTemplateRenderer`, or an
   equivalent symbol — name discovered at read-time) and produce a
   reference sheet of substitution rules **before** Phase 3 commits any
   SUB fixture. The reference sheet is appended to this OQ as the
   resolution; rows 68–75 capture the rendered shape into goldens
   regardless of which branch the engine takes, so this OQ does not
   block authoring of the fixtures, only their early review.

10. **OQ-SUITE-10 — Pipstub control surface shape (correction on D-O
    assumption).** Phase 1 reading of
    [tests/integration/pipstub/main.go](../../../test/integration/pipstub/main.go)
    surfaced three ways in which the real control surface diverges
    from the one D-O speculated about. This does not change the
    decision — D-O is still satisfied by the real surface, which is
    a strict superset in the relevant dimensions — but it means the
    Go `pip_control.go` helper, the Phase 3 seed extension, and the
    Phase 4 test `SetupTest` hooks must use the corrected endpoints
    and be aware of the caveats. Summary of the divergences:
    1. **Control path is `PUT/POST /pip-stub/configure`**, not
       `POST /__mock__/responses`. The request body is a JSON array
       of `{"path":"<literal>","responses":[{"statusCode":<int>,"body":<any>,"bodyRaw":"<string>"}]}`.
       Configuring the same path twice overwrites the previous
       responses (map upsert, not list append).
    2. **`GET /pip-stub/reset` only clears `calls` and `counters`**,
       not `routes`. Previously-registered routes persist. Tests
       that want a clean slate must either (a) overwrite every
       previously-pinned path with fresh responses, or (b) pin a
       404 fallback and rely on the "no route → 404" default
       ([pipstub/main.go:110-115](../../../test/integration/pipstub/main.go#L110-L115)).
       Phase 4 must encode this in the suite-wide `TearDownTest`
       via the `pip_control.go` helper — the helper tracks every
       path it has pinned in this suite run and re-issues an empty-
       response configure for each on teardown, so the next test's
       `SetupTest` starts from a known state even though the route
       map itself is mutable.
    3. **Path matching is strictly literal.** No wildcard / regex /
       template matching. This is the item that blocks D-U's V3 per-
       user entitlements endpoint without a workaround — see
       **OQ-SUITE-11** below.
    **What to do:** Phase 2 implements the corrected wire shape in
    `tests/parity/suite/pip_control.go` and documents the "configure
    is upsert, reset does not unregister, path matching is literal"
    caveats at the top of that file. No edit to `tests/integration/pipstub/`
    is needed for Phase 2 — the corrections are caller-side only.
    D-O's "extend pipstub additively" fallback is preserved as the
    escape hatch for **OQ-SUITE-11**. Phase 4 re-reads this OQ
    before wiring each test's `SetupTest`, so no individual test
    authors stumble into the "reset does not unregister" foot-gun.
11. **OQ-SUITE-11 — Pipstub literal-path matching vs D-U templated
    EA routes.** D-U specifies that the `entitlements-mock` service
    must answer
    `GET /api/v3/user-entitlements/user/{userId}?...` and
    `GET /api/v3/user-entitlements/user/{userId}/resource-type/{rt}/name/{name}`
    for every user the ENT block exercises. Pipstub's path matching
    is literal (see **OQ-SUITE-10** item 3), so the mock cannot
    answer `/api/v3/user-entitlements/user/42` with a
    `/api/v3/user-entitlements/user/{userId}` registration. Three
    workaround options (all preserve D-O / D-U without editing the
    pipstub binary for the Phase 2 gate):
    1. **Pre-pin every user id in `SetupTest`.** Each ENT test knows
       which `parity-*` user profile it exercises (`parity-reader`,
       `parity-reviewer`, …); the test's `SetupTest` calls
       `PinEntitlements(userID, body)` on the Go helper, which
       issues a `PUT /pip-stub/configure` with the fully-resolved
       literal path `/api/v3/user-entitlements/user/<actual-id>?...`.
       Per-user-id pinning works because the suite uses a fixed set
       of test users per **D-N**, not randomly-generated ids. This
       is the zero-code-change path and the one Phase 4 should take
       by default.
    2. **Additive pipstub extension.** If workaround 1 ever hits a
       wall (for example, a test that dynamically generates user ids
       at runtime), Step 2 **D-D**'s additive-extension allowance
       kicks in: pipstub gains a path-template matcher that accepts
       `/api/v3/user-entitlements/user/:userId/...` registrations
       and matches them against incoming requests. The extension
       must be strictly additive — existing literal-path behavior
       stays intact — and must be justified in a new decision line
       in this handover before Phase 3 lands it.
    3. **Dedicated EA-mock binary.** Rejected in iteration 6 per
       **D-U** ("Use a wholly separate mock binary under
       `tests/parity/eastub/` — rejected…"). Not reconsidered here.
    **Decision for Phase 2:** take option 1 by default. The Go
    `pip_control.go` helper exposes both a generic `PinRoute(path,
    body)` method and an ENT-specific `PinEntitlementsV3ForUser(userID,
    body)` method that resolves the literal path once and forwards to
    `PinRoute`. Phase 4 ENT tests call the specific method; the
    generic method stays available for any future row that needs a
    different EA path shape. Option 2 is held in reserve and will
    only be exercised if Phase 4 discovers a fixture that option 1
    cannot express.

### Execution Report

**Final closure — 2026-04-14 fifth session (O6 landing).** The post-closure
architectural follow-up is now complete in the working tree. Compose no longer
owns PAP seeding: `tests/parity/suite/seed.go` and `smoke.go` moved the smoke
and main fixture lifecycle into `ParitySuite.SetupSuite` under the locked
four-phase order `smoke seed -> smoke run -> wipe -> main seed -> tests`.
`tests/parity/compose/docker-compose.yml` no longer defines `ac-seed`;
`tests/parity/scripts/smoke.sh` and
`tests/parity/compose/seed/scripts/seed-access-control.sh` are deleted; the
fixture tree lives under `tests/parity/suite/testdata/fixtures/`. Verified on
`2026-04-14`: cold `bash tests/parity/scripts/run-parity-suite.sh` run
completed in `45.43s`, warm run completed in `1.57s`, both printed
`[paritysuite] smoke phase: 12/12 assertions green` and
`Parity suite passed: 130/130 cases green.`, `*.observed.json` count stayed
`0`, `docker compose ps` showed the parity stack healthy, and the CLI-equivalent
of `.run/authz-agent parity suite debug.run.xml` passed all 130 leaves with the
same four SetupSuite phases. No Step 3 follow-up remains open; Step 4 drafting
is unblocked again.

### Session summary (2026-04-14 fifth session)

1. Moved seeding + smoke ownership into the Go suite:
   - added `tests/parity/suite/seed.go` for PAP wipe/seed orchestration;
   - added `tests/parity/suite/smoke.go` for the 12-step smoke phase;
   - rewired `suite_test.go` so `SetupSuite` now runs smoke seed, smoke run,
     wipe, and main seed before the catalogue.
2. Removed the compose/bash lifecycle:
   - deleted compose `ac-seed`;
   - deleted `tests/parity/scripts/smoke.sh`;
   - deleted `tests/parity/compose/seed/scripts/seed-access-control.sh`;
   - simplified `tests/parity/scripts/run-parity-suite.sh` to
     `docker compose up -d -> wait healthy -> go test`.
3. Relocated fixtures into Go-owned `testdata`:
   - smoke fixtures moved to `tests/parity/suite/testdata/fixtures/smoke/`;
   - main simplified fixtures moved to
     `tests/parity/suite/testdata/fixtures/policies/suite/`;
   - regular full-policy fixtures moved to
     `tests/parity/suite/testdata/fixtures/policies/regular/`.
4. Closed the two runtime regressions surfaced during O6 validation:
   - restored the old main-seed ordering so the smoke baseline loads before
     the suite simplified pack;
   - isolated the smoke GENERAL-PIP cache from reader-based suite rows by
     running the smoke GENERAL-PIP assertions with `parity-multi-role`.
5. Revalidated the developer workflows:
   - cold and warm `run-parity-suite.sh` reruns stayed at `130/130`;
   - `.run/authz-agent parity suite debug.run.xml` was verified via its
     exact CLI-equivalent `go test` invocation and env block;
   - `docker compose config` and `go test -tags integration -run '^$' ./...`
     stayed green after the refactor.

**Final closure — 2026-04-14 fourth session.** Step 3 is functionally
complete in the working tree. The legacy parity suite now covers all
83 catalogue rows as **130 leaf testify sub-cases**, with **127** golden
JSON files under `tests/parity/suite/testdata/golden/`. The last two
runtime blockers were closed in this session: **OQ-SUITE-12** by adding
the regular full-policy seed channel for PSUITE row 22 + SUB rows 71/72/73,
and the final cold-only stability gap by canonicalizing the order-unstable
RSQL union in `agg-two-predicates`. Verification on `2026-04-14`:
`smoke.sh` stayed `12/12`; `go build -tags integration ./...` and
`go vet -tags integration ./...` exited `0`; a cold full-suite run
completed in `49.45s`; a warm full-suite run completed in `1.47s`; and
two consecutive non-record runs printed
`Parity suite passed: 130/130 cases green.` with `0`
`*.observed.json` sidecars left behind.

### Session summary (2026-04-14 fourth session)

1. Closed the last seed/config gaps:
   - removed the unsupported prohibited-header HEADER PIP path for row 48
     and rewired the row onto the OLS baseline transport check;
   - added the regular full-policy import channel under
     `tests/parity/compose/seed/policies/regular/` so PSUITE row 22 and
     SUB rows 71/72/73 are covered on the legacy stack.
2. Landed the remaining parity-suite coverage:
   - completed the bulk / preview / filter fixture-dependent slices;
   - completed the ENT block against `entitlements-mock`;
   - recorded the remaining golden files, bringing the tree to
     `127` JSON goldens.
3. Closed the final stability issue:
   - fixed the cold-only `agg-two-predicates` drift by canonicalizing the
     order-unstable top-level RSQL union in the comparator.
4. Final verified outcome of the session:
   - `smoke.sh` stayed `12/12`;
   - `go build -tags integration ./...` and `go vet -tags integration ./...` stayed green;
   - `run-parity-suite.sh` printed `Parity suite passed: 130/130 cases green.`
     on record mode, on two consecutive non-record runs, and on the measured
     cold/warm runs.

**Phase 1 + Phase 2 execution — 2026-04-14 (partial; Phases 3–7 still open).**
**Phase 3 infrastructure slice — 2026-04-14 (partial; fixture pack + seed-script
extension deferred to next session — see [§Phase 3 — Infrastructure slice
(2026-04-14)](#phase-3--infrastructure-slice-2026-04-14)).**
**Phase 4 + Phase 5 + Phase 6 base-endpoint slice — 2026-04-14 (partial;
18 of the 83 rows implemented — rows 1–10 base endpoints + validation
rows 11/16/29 + anonymous sub-case — against the Step 2 bespoke smoke
fixtures only. CLANG / AGG / SUB / ENT blocks still blocked on the
Phase 3 fixture-pack slice and OQ-SUITE-6/8/9. See
[§Phase 4 + 5 + 6 — Base-endpoint slice (2026-04-14)](#phase-4--5--6--base-endpoint-slice-2026-04-14).)**

### Implemented changes

1. **Handover Transport Convention Inventory filled** (this file,
   [§Transport Convention Inventory](#transport-convention-inventory)):
   Row→Helper→Struct map covers parity-contract Summary Table rows
   1–10 with concrete file:line citations; D-V wire-item check table
   covers items 1–14 with one row each and no new items added; legacy
   semantics sub-section grounds anonymous-subject, wildcard-role,
   CLANG/SUB/AGG/ENT, mock-PIP control-surface, entitlements wire
   shape, and seed-idempotency findings. Two new Open Questions raised
   (OQ-SUITE-10 pipstub control surface correction, OQ-SUITE-11
   pipstub literal-path vs D-U EA routes), both resolved in-place
   for Phase 2 and flagged forward for Phases 3–4.
2. **Go module bootstrap at `tests/parity/suite/`** (Phase 2 gate
   artifact per **D-A** / **D-B** / **D-I**):
   - `go.mod` (module `authz-agent/tests/parity/suite`; direct deps
     `github.com/stretchr/testify v1.9.0`, `github.com/google/go-cmp
     v0.6.0`, `github.com/golang-jwt/jwt/v5 v5.2.1`). Module path
     chosen to mirror
     `authz-agent/tests/integration/testify` per **D-I**'s naming
     convention guidance and **D-I** of this handover is now
     filled.
   - `go.sum` resolved by `go mod tidy` against the three direct
     deps + their transitive closure (`davecgh/go-spew`,
     `pmezard/go-difflib`, `gopkg.in/yaml.v3`).
   - `suite_test.go` (build tag `//go:build integration`) —
     `ParitySuite` struct embedding `suite.Suite`, `SetupSuite` that
     reads `PARITY_PROFILE` + `PARITY_GOLDEN_RECORD` and fails fast
     per **D-F** when record mode is combined with a non-`legacy`
     profile, and `TestParitySuite` entry point. Zero matching test
     methods at this gate — Phase 4 adds the 83 rows.
   - `config.go` — env-driven `Config` struct with the `PARITY_*`
     env-var block listed in Deliverables §1.4 (AC base URL, IdP
     base URL, M2M + end-user client credentials, pip-mock control
     URL, EA mock control URL, tenant id, domain name, profile,
     record flag). Defaults align with the Step 2 port map
     (`PARITY_AC_PORT=28090`, `PARITY_PIP_PORT=28091`,
     `PARITY_IDP_PORT=25557`).
   - `tokens.go` — `TokenFactory` with `M2MToken()` and
     `EndUserToken(UserProfile)`; `UserProfile` is a Go `type int`
     enum with the seeded users per **D-N**
     (`PARITY_READER`, `PARITY_REVIEWER`, `PARITY_MULTI_ROLE`,
     `PARITY_OTHER`, `PARITY_ANON_BASELINE`). Token acquisition uses
     Resource-Owner-Password-Credentials grant against the
     `parity-end-user` client for end-user tokens and
     `client_credentials` grant against `parity-m2m` for M2M
     tokens. Helpers copied (with attribution) from
     `tests/integration/testify/helpers.go` per **D-I**.
   - `helpers.go` — shared HTTP client, `applyAuthHeaders`,
     `filterCustomHeaders`, `buildQuery`, and the base
     `doRequest` primitive that every wire helper funnels through.
     Enforces **D-V** items 1–7 and 14 at the wire level; items 8,
     12, 13 are enforced by the `model/*.go` struct JSON tags.
   - `wire_v1.go` — `HelperApiVersion`, `HelperCheckResourceV1`,
     `HelperCheckResourcesV1`, `HelperCheckResourcesByOperationsV1`,
     `HelperPreviewCheckResourcesByOperationsV1`, `HelperFilterV1`.
     One function per parity-contract row 1–6. Each takes a
     `TokenBundle`, an optional `customHeaders` map, and a
     `PerCallOptions{UserID string}` struct; returns `(status int,
     body []byte, decoded any, err error)` so tests can assert on
     either the raw wire bytes (for validation rows) or the decoded
     typed response (for golden-asserted rows). Decoded type is
     selected per row.
   - `wire_v2.go` — `HelperCheckResourceV2`, `HelperCheckResourcesV2`,
     `HelperPreviewCheckResourcesV2`, `HelperFilterV2`. Every v2
     helper appends `obligations=false` unconditionally per **D-E**
     / **D-V** item 9.
   - `catalog.go` — `ParityEndpointId` Go `type int` enum with one
     constant per parity-contract row (`PSUITE_ROW_1_API_VERSION`
     through `PSUITE_ROW_10_FILTER_V2`) plus a `RowMeta` table with
     HTTP method, path template, and expected response shape for
     each row; a `RowToGoldenFactory` lookup map returns a fresh
     zero-value struct pointer per row per **D-M**.
   - `compare.go` — `GoldenComparator` struct with `Compare(row,
     goldenPath, actual)` and `Record(row, goldenPath, actual)`
     methods. `Compare` reads the golden via `json.Unmarshal` into
     the row's factory-created struct, unmarshals the `actual`
     response the same way, and runs `cmp.Diff` with `cmpopts.SortSlices`
     for rows 3/4/5/8/9 and `cmpopts.IgnoreFields(...,"Obligations")`
     for rows 7/8/9/10 per **D-M**. On mismatch, writes
     `<goldenPath>.observed.json` next to the golden and returns a
     `GoldenMismatchError` with the diff. The ignore-list is
     defended inline with a one-line justification — only
     `Obligations` is pre-committed; any further additions require
     a comment + OQ reference.
   - `record.go` — record-mode writer gated by `PARITY_GOLDEN_RECORD=1`
     - `PARITY_PROFILE=legacy` per **D-F**. `SetupSuite` invokes
     `record.EnsureSafe(cfg)` which panics in `SetupSuite` before
     any test runs when the guard fails.
   - `pip_control.go` — `PipController` wraps `PUT /pip-stub/configure`
     and `GET /pip-stub/reset` with the **OQ-SUITE-10** corrections
     baked in. Exposes `PinRoute(path, statusCode, body)`,
     `PinEntitlementsV3ForUser(userID, body)` (literal path
     resolution per **OQ-SUITE-11** option 1), `ResetCalls()` (clears
     calls + counters only), and `ResetPinnedRoutes()` (re-issues an
     empty-response configure for every path pinned in this suite
     run, tracked in an internal `sync.Mutex`-guarded map). Every
     method has a package-level comment citing the pipstub
     file:line it wraps.
   - `model/api_version.go` — `ApiVersionResponse{Specs []ApiVersionSpec
     [json:"specs"]}` and `ApiVersionSpec{SpecRootUrl string, Major
     int, Minor int, SupportedMajors []int}`; integer-typed per
     **D-V** item 11.
   - `model/check_resource.go` — `CheckAccessRequest` (v1 request
     body), `CheckAccessRequestWithID` (v1 bulk entry with
     `ID *string` + `omitempty` per **D-V** item 8), `CheckAccessBulkOperationsRequest`
     (v1 bulk/operations entry), `CheckResourceRequest` (v2 request),
     `CheckResourceResponse` (v2 response with `Decision bool` and
     `Obligations json.RawMessage [json:"obligations,omitempty"]`
     — `Obligations` is the only field on the ignore-list per **D-E**).
   - `model/check_resources.go` — `CheckResourcesRequest` (v2 bulk
     container), `CheckResourcesRequestEntry` (v2 bulk entry with
     `ID *string` + `omitempty`), `CheckResourcesResponse` (v2 bulk
     response with `Decision map[string][]string` and `Obligations
     json.RawMessage`).
   - `model/filter.go` — `OldFilterEvaluationResult` (v1 filter
     response) and `FilterResponse` (v2 filter response). Both
     structs share `CalculationResult string [json:"calculationResult"]`,
     `FilterCondition string`, `MongodbFilterCondition string`,
     `RsqlFilterCondition string`, `SqlFilterCondition string`,
     `CustomFilterCondition json.RawMessage`. `FilterResponse` also
     has `Obligations json.RawMessage [json:"obligations,omitempty"]`.
   - `model/entitlements.go` — `GetDirectUserEntitlementsResponse`,
     `Entitlement`, `EntitlementReference`, `EntitlementDefinition`,
     typed off the legacy EA wire shapes per **D-U**. Not consumed
     by any row in Phase 2 — they exist so Phase 3 seed extension
     and Phase 4 ENT tests can pin EA mock responses against a
     typed struct instead of `map[string]any`.
   - `testdata/golden/.gitkeep` — placeholder to commit the empty
     directory so the tree is ready for Phase 5 captures without
     a second "add directory" commit.

### File manifest (Phase 2, 2026-04-14 bootstrap)

| File                                          | Lines | Role                                                              |
| --------------------------------------------- | ----- | ----------------------------------------------------------------- |
| `tests/parity/suite/go.mod`                   | 15    | Module declaration (`authz-agent/tests/parity/suite`, go 1.22.0)  |
| `tests/parity/suite/go.sum`                   | —     | Resolved by `go mod tidy`                                         |
| `tests/parity/suite/config.go`                | 104   | `PARITY_*` env-driven `Config` + `LoadConfig`                     |
| `tests/parity/suite/tokens.go`                | 184   | `TokenFactory` + `UserProfile` enum + Keycloak grant flows        |
| `tests/parity/suite/helpers.go`               | 143   | Transport helpers (D-V 1–7, 14), HeadersFilter, decodeJSON        |
| `tests/parity/suite/wire_v1.go`               | 171   | Rows 1–6 HTTP helpers (GET /api-version + v1 check/filter family) |
| `tests/parity/suite/wire_v2.go`               | 117   | Rows 7–10 HTTP helpers with unconditional `obligations=false`     |
| `tests/parity/suite/catalog.go`               | 136   | `ParityEndpointID` enum + `rowMetas` + `NewGoldenTarget`          |
| `tests/parity/suite/compare.go`               | 135   | `GoldenComparator` (D-M) + `GoldenMismatchError`                  |
| `tests/parity/suite/record.go`                | 17    | `EnsureRecordModeSafe` (D-F guard)                                |
| `tests/parity/suite/pip_control.go`           | 177   | `PipController` wrapping the real pipstub surface per OQ-SUITE-10 |
| `tests/parity/suite/suite_test.go`            | 60    | `//go:build integration` ParitySuite + `TestParitySuite` entry    |
| `tests/parity/suite/model/api_version.go`     | 22    | Integer-typed `ApiVersionResponse` + `ApiVersionSpec` (D-V 11)    |
| `tests/parity/suite/model/check_resource.go`  | 53    | v1 + v2 request/response DTOs                                     |
| `tests/parity/suite/model/check_resources.go` | 34    | v2 bulk request/response DTOs                                     |
| `tests/parity/suite/model/filter.go`          | 40    | v1 `OldFilterEvaluationResult` + v2 `FilterResponse`              |
| `tests/parity/suite/model/entitlements.go`    | 40    | `GetDirectUserEntitlementsResponse` + friends (ENT block prep)    |
| `tests/parity/suite/testdata/golden/.gitkeep` | 2     | Placeholder so Phase 5 captures into a committed tree             |

**Total Go source under `tests/parity/suite/` at Phase 2 close:** 18 files,
**~1431 lines** (counting `.go` files only; `go.sum` + `.gitkeep` are not
source).

### Validation performed

All three commands were run from the module root
`tests/parity/suite/` on 2026-04-14:

1. `go mod tidy` — resolved the direct deps (`testify v1.9.0`,
   `go-cmp v0.6.0`) plus the three transitive deps
   (`davecgh/go-spew v1.1.1`, `pmezard/go-difflib v1.0.0`,
   `gopkg.in/yaml.v3 v3.0.1`). `golang-jwt/jwt/v5` was removed by
   tidy because nothing in the Phase 2 skeleton imports it yet; it
   will re-enter `go.mod` when Phase 4 tests parse tokens for
   assertion. This matches **D-I**'s "direct deps" list as a
   super-set — no new dep entered the module.
2. `go build -tags integration ./...` — exit 0. Both the root
   package (`paritysuite`) and the `model` subpackage compile clean.
3. `go vet -tags integration ./...` — exit 0 after swapping one
   `s.T().Context()` call (requires go1.24) for `context.Background()`
   to stay compatible with the module's declared `go 1.22.0`.
4. `go test -tags integration -run '^$' ./...` — exit 0 with
   `ok authz-agent/tests/parity/suite 0.003s [no tests to run]`
   on the root package and `?  authz-agent/tests/parity/suite/model
   [no test files]` on the model subpackage. **This is the
   Phase 2 gate** per the handover's Method §4.
5. `run-parity-suite.sh` — **not** invoked. Phase 2 deliberately
   does not bring the legacy stack up; that is the Phase 3 + Phase 6
   gate. No goldens captured, no record-mode run.
6. Step 2 `tests/parity/scripts/smoke.sh` — **not** run in this
   session. Phase 2 does not touch the Compose stack, any seed
   fixtures, or the `ac-seed` container. The next session (Phase 3)
   runs `smoke.sh` once before the seed extension and once after,
   recording both observations per **D-H**.

### Remaining gaps (Open Questions after Phase 1 + Phase 2)

1. **OQ-SUITE-6** — CLANG operator spelling inventory. Deferred to
   Phase 3 fixture design as previously drafted.
2. **OQ-SUITE-8** — Pure-OLS-row + RLS-row combining shape for AGG
   row 64. Deferred to Phase 3 / Phase 4.
3. **OQ-SUITE-9** — SUB block substitution escaping rules. Deferred
   to Phase 3 / Phase 4 per **D-T**.
4. **OQ-SUITE-10** — Pipstub control surface shape. Resolved in-place
   for Phase 2 (`pip_control.go` uses the real endpoints). Phase 4
   test authors must re-read the OQ to avoid the "reset does not
   unregister" foot-gun.
5. **OQ-SUITE-11** — Pipstub literal-path matching vs D-U's templated
   EA routes. Resolved by option 1 (per-user pre-pin) for Phase 2;
   option 2 (additive pipstub extension) is the documented escalation
   if Phase 4 ENT tests hit a case option 1 cannot express.

### Scenarios deferred to later phases

1. **All 83 test rows** — Phase 4 work, not started. Phase 2 only
   ships the helper layer + DTOs + catalog + comparator + record-mode
   guard. No test method bodies are written in this session.
2. **Phase 3 seed extension** — not started. The Phase 2 skeleton
   compiles standalone without touching `tests/parity/compose/seed/`.
3. **Phase 5 golden capture** — not started; `testdata/golden/`
   contains only a `.gitkeep`.
4. **Phase 6 `run-parity-suite.sh`** — not started. The existing
   Step 2 scripts (`smoke.sh`, `build-images.sh`) are untouched.
5. **Phase 7 documentation updates** — not started. The README
   update, the parent plan Step 3 flip, and the ADR filing
   (conditional) are all pending Phase 7.

### Next-session starting point

The next executor picks up at **Phase 3**:

1. Run `bash tests/parity/scripts/smoke.sh` once against the Step 2
   stack and record the observation in this Execution Report
   (expected: `Smoke run passed: 12/12 checks green.`).
2. Implement the Phase 3 seed extension per the handover's Phase 3
   bullet list (fixtures per row, `parity-realm.json` additive edit,
   `entitlements-mock` compose service per **D-U**).
3. Re-run `smoke.sh` after the seed extension and after the
   compose edit; record both.
4. Move on to Phase 4 (test catalogue implementation) — this is
   where the 83-row grind begins, ideally split across multiple
   sessions per parity-contract row so each row can be recorded,
   inspected, and committed before the next starts.

The Go module at `tests/parity/suite/` is the stable anchor for
Phases 3–7: everything under that directory compiles today, so
each Phase 4 row landing is an incremental test-file addition,
not a module-structure change.

### Phase 3 — Infrastructure slice (2026-04-14)

Phase 3 was split into an **infrastructure slice** (this session) and a
**fixture-pack slice** (next session). The infrastructure slice lands
the three changes that must exist before any fixture file can be
written — realm users/claims, the entitlements-mock service, and the
AC env wiring to reach it — without touching the seed script or
seeding any new policy rows, so that the existing Step 2 `smoke.sh`
stays 12/12 green through the slice.

### Implemented changes (Phase 3 infrastructure slice)

1. **`tests/parity/compose/idp-seed/parity-realm.json` extended
   additively per **D-N** of the Phase 3 plan.**
   - **Roles added:** `ROLE_PARITY_REVIEWER` (secondary single-role
     locator used by AGG / SUB / multi-role rows) and
     `ROLE_PARITY_OTHER` (isolation role — no seed policy addresses
     it, so any check against it is a guaranteed DENY with a valid
     end-user token, which the suite needs to distinguish
     "role-does-not-grant" from "no-token-at-all" failures). Step 2
     roles (`ROLE_samples-repository`, `ROLE_M2M`, `ROLE_PARITY_READER`)
     are preserved byte-for-byte so the existing ac-seed PUT path
     stays green.
   - **Password-grant client added:** `parity-end-user` (confidential,
     secret `ParityEndUserSecret1!@#`, `directAccessGrants=true`,
     `serviceAccounts=false`, no `netcracker` audience mapper). Minted
     exclusively by the Go suite's `TokenFactory.EndUserToken` flow;
     kept separate from `parity-m2m` so (a) secret rotation here does
     not touch ac-seed's M2M path, and (b) end-user tokens minted by
     this client are not eligible for M2M auth, so the
     `Incoming-Token` relay contract stays observable.
   - **Protocol mappers on `parity-end-user`:** two
     `oidc-usermodel-attribute-mapper` entries emit `department` and
     `tier` JWT claims from user attributes of the same name. These
     are the TOKEN-PIP claims Phase 3 fixtures (rows 5/25/43/47/65/71
     in the parity contract) will read via `subject.<alias>`.
     `id.token.claim=false`, `access.token.claim=true`,
     `userinfo.token.claim=false` — the claims exist only on the
     access token the AC thin client relays as `Incoming-Token`.
   - **Users added** (additive; existing `parity-reader` preserved
     byte-for-byte and now carries `department=finance`, `tier=gold`
     attributes for its own TOKEN-PIP coverage):
     - `parity-reviewer` — `ROLE_PARITY_REVIEWER`, `department=compliance`,
       `tier=silver`, password `ParityReviewer1!@#`.
     - `parity-multi-role` — both `ROLE_PARITY_READER` and
       `ROLE_PARITY_REVIEWER`, `department=engineering`,
       `tier=platinum`, password `ParityMulti1!@#`.
     - `parity-other` — `ROLE_PARITY_OTHER` only,
       `department=sales`, `tier=bronze`, password `ParityOther1!@#`.
     - `parity-anon-baseline` — empty `realmRoles` (no parity role),
       `department=guest`, `tier=none`, password `ParityAnon1!@#`.
       Tokens for this user are acquired and then dropped by the
       suite when `Authorization-Type: anonymous` is set per **D-V**
       item 4; the point of seeding it is to contrast "anonymous
       flow reached the engine with no roles" against "named user
       with a token reached the engine with no parity roles", which
       are two materially different code paths in legacy AC.
2. **`tests/parity/compose/docker-compose.yml` extended for D-U.**
   - New `entitlements-mock` service block (image `pip-stub:local`,
     container `parity-entitlements-mock`, internal port 8080 via
     `PIP_STUB_PORT=8080`, host port `${PARITY_EA_PORT:-28092}`,
     healthcheck parity with `pip-mock`, on the `parity` network).
     Uses the **same** `pip-stub:local` binary as `pip-mock` rather
     than a separate image per **D-U** — the stub is method- and
     body-agnostic, so pinning the four EA endpoints
     (`GET /api-version`, `POST /api/v1/entitlements-aggregator/entitlements`,
     `GET /api/v3/user-entitlements/user/{userId}`,
     `GET /api/v3/user-entitlements/user/{userId}/resource-type/{rt}/name/{name}`)
     requires no code change, only per-test `POST /pip-stub/configure`
     calls that Phase 4 ENT rows will drive through the Go
     `PipController`.
   - **Compose service list is otherwise unchanged** per Phase 3 item
     8.3 — no existing image, healthcheck, or volume is touched.
   - **`access-control` service** gains:
     - `depends_on: entitlements-mock: service_healthy`, matching
       its existing gate on `pip-mock` so AC does not boot before
       the mock is reachable.
     - `ACCESS_CONTROL_ENTITLEMENTS_AGGREGATOR_URL=http://entitlements-mock:8080`
       replacing the Step 2 `http://idp:8080` fast-fail dummy.
     - `ACCESS_CONTROL_ENTITLEMENTS_CACHE_ENABLED=false` so
       per-test pin/reset in Phase 4 takes effect immediately and
       cache staleness cannot mask a Phase 5 golden mismatch.

### Validation performed (Phase 3 infrastructure slice)

1. **Baseline `smoke.sh` run (before any Phase 3 edit)** against the
   Step 2 stack on a fresh `docker compose up -d` — recorded:
   `Smoke run passed: 12/12 checks green.` (all 12 checks listed
   individually in the smoke script).
2. **Full stack teardown + rebuild** via
   `docker compose -f tests/parity/compose/docker-compose.yml down -v`
   then `docker compose ... up -d` after the edits landed. All six
   services reached `(healthy)` in ~60s cold start
   (`parity-postgres` 5s, `parity-pip-mock` 5s,
   `parity-entitlements-mock` 5s, `parity-idp` ~45s,
   `parity-ac-token-fetcher` ~55s, `parity-access-control` ~70s);
   `parity-ac-seed` exited 0 and was removed.
3. **Post-edit `smoke.sh` run** — recorded:
   `Smoke run passed: 12/12 checks green.` identical to the
   baseline. Confirms the realm + compose extensions did not
   regress the Step 2 surface per **D-H**.
4. **End-user token mint smoke-check** against the new
   `parity-end-user` client — executed via
   `curl -d grant_type=password ... parity-reviewer/ParityReviewer1!@#`
   and decoded the JWT payload. Observed claims:
   `realm_access.roles=["ROLE_PARITY_REVIEWER"]`,
   `department="compliance"`, `tier="silver"`,
   `preferred_username="parity-reviewer"`. Claims route through
   the access token (not ID token) per the protocol-mapper config.
5. **Multi-role user mint check** (`parity-multi-role` /
   `ParityMulti1!@#`) — observed
   `realm_access.roles` ⊇ `{ROLE_PARITY_READER, ROLE_PARITY_REVIEWER}`,
   `department=engineering`, `tier=platinum`. Confirms the multi-role
   AGG fixture locator (one user holding two parity roles on the
   same evaluation) is actually reachable from the IdP; not just a
   realm-JSON assertion.
6. **Backwards-compat probe for smoke.sh token path** — minted
   `parity-reader` via the original `parity-m2m` password grant
   (the path Step 2's `smoke.sh` step [3/12] uses) and observed
   the token shape is unchanged. Parity-reader is a member of both
   mint paths now (via `parity-m2m` for smoke.sh, via
   `parity-end-user` for the Go suite); no path is broken.
7. **entitlements-mock reachability probe** — ran
   `docker exec parity-access-control wget -qO-
   http://entitlements-mock:8080/pip-stub/calls`
   and observed `[]` (empty call log, HTTP 200). Confirms Compose
   DNS resolves `entitlements-mock` inside the `parity` network and
   that AC-side traffic can reach the mock. Also probed the host
   port publication — `curl http://localhost:28092/pip-stub/calls`
   returned `[]` — so Phase 4 Go tests can drive the mock via
   `PARITY_EA_MOCK_CONTROL_URL=http://localhost:28092` without
   needing a Compose exec shim.

### Remaining Phase 3 work (deferred to next session)

The **fixture-pack slice** of Phase 3 covers items 1–6 and 9 of the
Phase 3 bullet list (the expanded seed policy/PIP fixtures + seed
script extension + ENT policy fixtures) and is intentionally not
landed in this session. Reasons:

1. **OQ-SUITE-6 unresolved** — the CLANG operator/keyword spelling
   grammar accepted by legacy `SimplifiedConditionEvaluator` is not
   yet inventoried from `sample-sources/access-control/`. Writing
   rows 49–60 fixtures without that inventory produces guessed
   spellings (`==` vs `=`, `IN (...)` vs `IN[...]`, `CONTAINS ANY`
   vs `contains-any`, `null` vs `NULL`, etc.) that the legacy PUT
   rejects with HTTP 400 at seed time and blocks the whole suite.
   Phase 3 Phase 1 (the reading pass) explicitly gates fixture
   writing on OQ-SUITE-6 resolution.
2. **OQ-SUITE-8 unresolved** — the shape the legacy
   `PolicyRuleAggregator` produces for pure-OLS-row + RLS-row
   combining (AGG row 64) is not yet documented. Without it the
   Phase 3 seed cannot decide whether rows 63 and 64 share a
   locator or need distinct ones to remain deterministic.
3. **OQ-SUITE-9 unresolved** — the template-substitution renderer
   symbol + escaping rules for `${subject.<alias>}` placeholders
   in `rsqlPredicate` / `sqlFilterCondition` / `mongodbFilterCondition`
   are not yet documented. Writing SUB-block fixtures (rows 68–75)
   without that inventory produces guessed escaping that breaks
   on special-character rows (74, per the handover's SUB-special
   sub-bullet).
4. **ENT-block fixtures need the real EA wire-shape cross-check
   (D-U item 8.1 "Entitlements wire shape").** The Phase 3
   reading pass has not yet read
   `sample-sources/entitlements-aggregator/` and
   `EntitlementsPipServiceImpl.java:76-201` on a clean checkout
   to confirm the mock pin templates. Writing fixtures before
   the wire-shape cross-check risks mock drift that only
   Phase 4 ENT tests would catch.

**Scope staged for the next session:**

1. Resolve OQ-SUITE-6/8/9 via the Phase 1 legacy-server reading
   pass (`SimplifiedConditionEvaluator`, `PolicyRuleAggregator` /
   `RuleCombiner`, `SimplifiedPolicyRenderer` /
   `PredicateTemplateRenderer`). Record the findings in the
   Transport Convention Inventory §Legacy semantics sub-section.
2. Write the expanded fixture pack under
   `tests/parity/compose/seed/policies/suite/` (one directory per
   block: `ols/`, `rls/`, `token-pip/`, `header-pip/`,
   `general-pip/`, `clang/`, `agg/`, `sub/`, `ent/`). Each
   fixture carries a unique `(resourceType, operation)` locator
   per **D-L** and links back to its parity-contract row via an
   inline `_comment` field per the Step 2 convention (the
   `_comment` is stripped by the seed script before PUT per the
   existing `jq 'map(del(._comment))'` pipeline).
3. Extend `seed-access-control.sh` (or add a sibling script) to
   PUT the expanded pack idempotently alongside the existing four
   Step 2 fixtures, keeping the PIP-before-policy ordering
   discipline.
4. Run `smoke.sh` before and after the fixture-pack extension to
   prove regressions stay closed, and record both observations.
5. (Optional, early-Phase-4) Commit the fixture pack in small
   blocks (OLS/RLS first, then TOKEN/HEADER/GENERAL PIP, then
   CLANG/AGG/SUB/ENT) so each block can be smoked independently.

### File manifest (Phase 3 infrastructure slice, 2026-04-14)

| File                                              | Change               | Role                                                                                                                                                                                                                         |
| ------------------------------------------------- | -------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `tests/parity/compose/idp-seed/parity-realm.json` | rewritten additively | Adds 2 roles, 1 password-grant client with 2 claim mappers, 4 users with attributes; preserves existing `parity-m2m` + `parity-reader` byte-for-byte on the paths smoke.sh exercises                                         |
| `tests/parity/compose/docker-compose.yml`         | 2 edits              | Adds `entitlements-mock` service block (~30 lines); adds `depends_on: entitlements-mock` + `ACCESS_CONTROL_ENTITLEMENTS_AGGREGATOR_URL` + `ACCESS_CONTROL_ENTITLEMENTS_CACHE_ENABLED` to the `access-control` env (~8 lines) |

**Total Phase 3 infrastructure slice diff:** 2 files, ~200 added lines.
No file deleted, no existing line rewritten, no fixture/policy file
touched.

### Next-session starting point (Phase 3 fixture-pack slice)

1. Read the four legacy-server symbol chains named in **Remaining
   Phase 3 work** above and close OQ-SUITE-6/8/9.
2. Author the expanded fixture pack under `seed/policies/suite/`.
3. Extend `seed-access-control.sh` to load both the Step 2
   policies and the new `suite/` directory (PIP-before-policy
   discipline preserved).
4. Run `smoke.sh` before and after; record observations here.
5. Only after the fixture-pack slice is green, resume Phase 4 for
   the CLANG / AGG / SUB / ENT blocks (the base-endpoint slice of
   Phase 4 is already green — see
   [§Phase 4 + 5 + 6 — Base-endpoint slice (2026-04-14)](#phase-4--5--6--base-endpoint-slice-2026-04-14)).

### Phase 4 + 5 + 6 — Base-endpoint slice (2026-04-14)

Phase 4 was split into a **base-endpoint slice** (this session) and a
**fixture-dependent slice** (later sessions). The base-endpoint slice
covers every row of the parity-contract Summary Table whose assertion
can be expressed against the Step 2 bespoke smoke fixtures alone — no
expanded fixture pack needed, no Phase 3 fixture-pack slice
dependency, no OQ-SUITE-6/8/9 dependency. Phase 5 (goldens) and
Phase 6 (runner script) were landed end-to-end for this slice so that
the developer loop `record → inspect → commit → stability check` is
proven on real legacy output for the base endpoints, rather than
deferred until the whole fixture pack exists.

### Scope of the base-endpoint slice

The 18 tests below all use the four Step 2 policies
(`ols-allow.json`, `ols-deny.json`, `rls-filter.json`,
`general-pip.json`) and three `resourceType` locators
(`PARITY_CUSTOMER`, `PARITY_ORDER`, `PARITY_PAYMENT`). No new
simplified-policy row is seeded; every scenario is expressible by
choosing `(operation, resource.id, pinned pip-mock body)` combinations
on top of the existing fixtures.

| Row | Test method                                   | Sub-case             | Status                     |
| --- | --------------------------------------------- | -------------------- | -------------------------- |
| 1   | `TestRow01ApiVersion`                         | `m2m`                | Golden                     |
| 2   | `TestRow02CheckResourceV1AllowIncoming`       | `allow-incoming`     | Golden                     |
| 2   | `TestRow02CheckResourceV1DenyIncoming`        | `deny-incoming`      | Golden                     |
| 2   | `TestRow02CheckResourceV1GeneralPipAllow`     | `general-pip-allow`  | Golden                     |
| 2   | `TestRow02CheckResourceV1GeneralPipDeny`      | `general-pip-deny`   | Golden                     |
| 2   | `TestRow02CheckResourceV1AnonymousBaseline`   | `anonymous-baseline` | Golden                     |
| 3   | `TestRow03CheckResourceBulkV1Mixed`           | `mixed`              | Golden                     |
| 4   | `TestRow04CheckResourceBulkOperationsV1Mixed` | `mixed`              | Golden                     |
| 5   | `TestRow05PreviewBulkOperationsV1Mixed`       | `mixed`              | Golden                     |
| 6   | `TestRow06CheckFilterV1RlsHappy`              | `rls-happy`          | Golden                     |
| 7   | `TestRow07CheckResourceV2AllowIncoming`       | `allow-incoming`     | Golden                     |
| 7   | `TestRow07CheckResourceV2DenyIncoming`        | `deny-incoming`      | Golden                     |
| 8   | `TestRow08CheckResourceBulkOperationsV2Mixed` | `mixed`              | Golden                     |
| 9   | `TestRow09PreviewBulkOperationsV2Mixed`       | `mixed`              | Golden                     |
| 10  | `TestRow10CheckFilterV2RlsHappy`              | `rls-happy`          | Golden                     |
| 11  | `TestRow11ValidationMissingOperation`         | —                    | HTTP 400 assert, no golden |
| 16  | `TestRow16ValidationDuplicateIds`             | —                    | HTTP 400 assert, no golden |
| 29  | `TestRow29ValidationMissingResourceType`      | —                    | HTTP 400 assert, no golden |

**18 tests, 15 goldens, 3 validation rows without goldens.**

### Implemented changes (Phase 4 + 5 + 6 base-endpoint slice)

1. **Realm / smoke / Go config password alignment.** Phase 3 landed
   per-user passwords in `parity-realm.json` which clashed with
   Phase 2's `Config.EndUserPassword` single-value assumption. The
   realm, `smoke.sh` step [3/12], and `config.go` defaults are now
   aligned on the uniform password `ParityPass1!@#`:
   - `parity-realm.json` — every user (`parity-reader`,
     `parity-reviewer`, `parity-multi-role`, `parity-other`,
     `parity-anon-baseline`) carries `ParityPass1!@#`.
   - `smoke.sh` line 73 — parity-reader password literal updated to
     match; step [3/12] still mints through the `parity-m2m` client
     password-grant path so no smoke regression.
   - `config.go` — `M2MClientSecret` default → `ParityM2MSecret1!@#`,
     `EndUserClientSecret` default → `ParityEndUserSecret1!@#`,
     `EndUserPassword` default → `ParityPass1!@#`. The Phase 2
     placeholder `parity-m2m-secret` / `parity-end-user-secret` /
     `ParityPass1!` triplet is gone.
2. **Realm user UUIDs pinned** per Phase 5 stability discipline. The
   legacy engine renders `rsqlPredicate: "ownerId==${subject.id}"`
   into the `check/filter` response and the rendered predicate
   carries the caller's realm UUID. Without a pinned `id` field,
   Keycloak generates a fresh UUID on every `--import-realm` pass,
   which would break the "second run shows zero diff" stability gate
   across `down -v` + `up -d` cycles. Every parity user now has a
   fixed `id`:
   - `parity-reader` → `00000000-0000-0000-0000-000000000101`
   - `parity-reviewer` → `00000000-0000-0000-0000-000000000102`
   - `parity-multi-role` → `00000000-0000-0000-0000-000000000103`
   - `parity-other` → `00000000-0000-0000-0000-000000000104`
   - `parity-anon-baseline` → `00000000-0000-0000-0000-000000000105`
   The `check-filter-v1/rls-happy.json` golden carries
   `"rsqlFilterCondition": "ownerId==00000000-0000-0000-0000-000000000101"`
   verbatim; no regex substitution or field-ignore rule needed.
3. **Phase 4 test files** added under `tests/parity/suite/` — one
   file per row, all carrying the `//go:build integration` tag:
   - `test_row01_api_version_test.go`
   - `test_row02_check_resource_v1_test.go` (5 sub-cases — the
     allow-incoming / deny-incoming / general-pip-allow /
     general-pip-deny / anonymous-baseline quintet)
   - `test_row03_check_resource_bulk_v1_test.go`
   - `test_row04_check_resource_bulk_ops_v1_test.go`
   - `test_row05_preview_bulk_ops_v1_test.go`
   - `test_row06_check_filter_v1_test.go`
   - `test_row07_check_resource_v2_test.go` (2 sub-cases)
   - `test_row08_check_resource_bulk_ops_v2_test.go`
   - `test_row09_preview_bulk_ops_v2_test.go`
   - `test_row10_check_filter_v2_test.go`
   - `test_row11_validation_missing_op_test.go`
   - `test_row16_validation_duplicate_ids_test.go`
   - `test_row29_validation_missing_rt_test.go`
   Every test uses the Phase 2 HTTP helper layer (no raw
   `net/http` calls); every success row asserts through the
   `GoldenComparator` with the row id from `catalog.go`; every
   validation row asserts `status == 400` plus a substring check on
   the response body. Row 16's helper wraps a decode error when the
   server returns a JSON error envelope instead of the `Set<String>`
   success shape — the test ignores the wrapped error and asserts on
   status + raw body as the handover's Scope Note §7 mandates for
   validation rows.
4. **Goldens captured under `tests/parity/suite/testdata/golden/`**,
   15 files total, one directory per parity-contract row. Schema
   matches the per-row JSON DTOs declared in
   `tests/parity/suite/model/` byte-for-byte:
   - `api-version/m2m.json` — integer-typed `specs` block with
     `/access` (major 3), `/api` (major 1), `/template` (major 1),
     `/preview` (major 2) entries. Confirms **D-V** item 11's
     integer-byte-shape assertion against real legacy output.
   - `check-resource-v1/*.json` — five scalar `true`/`false`
     bodies (the v1 Boolean surface).
   - `check-resource-bulk-v1/mixed.json` — `["row3-A","row3-C"]`
     (sort-invariant via `cmpopts.SortSlices`).
   - `check-resource-bulk-operations-v1/mixed.json` — the
     legacy engine returns the response as `Map<operation, Set<id>>`
     rather than `Map<id, Set<operation>>`:
     `{"DELETE":["row4-A"],"READ":["row4-A"],"WRITE":[]}`. This
     is a material finding — the parity-contract Summary Table row
     4's response shape should be read as **"operation-keyed"**,
     not "id-keyed", which Step 4 must reproduce on the Authz
     Agent side.
   - `preview-bulk-operations-v1/mixed.json` — identical
     operation-keyed shape to row 4 via the `/preview` prefix.
   - `check-filter-v1/rls-happy.json` —
     `calculationResult=USE_FILTER_CONDITION`,
     `rsqlFilterCondition=ownerId==00000000-0000-0000-0000-000000000101`,
     every other predicate string empty. Confirms legacy's
     per-PREDICATE field-population pattern (only the RSQL field is
     rendered when the simplified policy carries an `rsqlPredicate`
     and no `sqlPredicate` / `mongodbPredicate`).
   - `check-resource-v2/*.json` — `{"decision": true/false}`
     (Obligations field ignored at compare time per **D-E**).
   - `check-resource-bulk-operations-v2/mixed.json` — same
     operation-keyed shape as row 4, wrapped in a `decision` envelope.
   - `preview-bulk-operations-v2/mixed.json` — same via `/preview`.
   - `check-filter-v2/rls-happy.json` — same fields as row 6 with
     Obligations filtered out by the comparator.
5. **Phase 6 runner script** `tests/parity/scripts/run-parity-suite.sh`
   added. One invocation:
   1. Brings the Compose stack up via
      `docker compose -f tests/parity/compose/docker-compose.yml up -d`
      iff nothing is running under that compose file.
   2. Waits up to 300s for every service to reach `(healthy)` and
      for `parity-ac-seed` to exit 0 (ac-seed is a one-shot
      container so it is not counted in the "all healthy" tally).
   3. Runs `tests/parity/scripts/smoke.sh` as a pre-flight and
      bails on any smoke failure.
   4. Runs `go test -tags integration -run '^TestParitySuite$'
      -count=1 -v ./...` under `tests/parity/suite/` with the
      `PARITY_*` env block exported from the host port map.
   5. On success prints the canonical
      `Parity suite passed: N/M cases green.` line (reported per
      `--- PASS: TestParitySuite/...` occurrences, so sub-case
      granularity per **D-X** is already correct — the 18 sub-cases
      in this slice print as `Parity suite passed: 18/18 cases green.`).
   6. On failure lists every `*.observed.json` sidecar the
      comparator wrote so the developer can diff it against the
      committed golden. Teardown stays manual per the Step 2
      workflow.

### Validation performed (Phase 4 + 5 + 6 base-endpoint slice)

1. **Stack cold-reboot with aligned passwords + pinned UUIDs** —
   `docker compose down -v` + `docker compose up -d`, ~70s to full
   health + `parity-ac-seed` exited 0.
2. **`go build -tags integration ./...`** from
   `tests/parity/suite/` — exit 0; all 13 new test files compile
   cleanly against the Phase 2 helper layer.
3. **`go vet -tags integration ./...`** — exit 0.
4. **First record-mode run** with
   `PARITY_PROFILE=legacy PARITY_GOLDEN_RECORD=1 go test -tags integration
   -run ^TestParitySuite$ -v ./...` — captured 15 golden files on
   disk. Row 16 failed on the first attempt because the helper
   wrapped a decode error (`Set<String>` unmarshaler over an error
   envelope); the test was patched to ignore that wrapped error and
   assert on status + raw body only. Re-run after the patch landed
   all 18 sub-cases PASS.
5. **Second run without record mode** — all 18 sub-cases PASS;
   `git status testdata/golden` shows zero diff; no
   `.observed.json` sidecar files. This is the Phase 7 stability
   check in miniature for the base-endpoint slice.
6. **`tests/parity/scripts/run-parity-suite.sh`** end-to-end —
   pre-flight smoke printed
   `Smoke run passed: 12/12 checks green.`; the Go suite ran to
   completion; the final line printed
   `Parity suite passed: 18/18 cases green.` verbatim.
7. **Wall-clock observation** — warm run (`run-parity-suite.sh`
   with the stack already up) finished in **~2 seconds** of Go
   test time plus the `smoke.sh` pre-flight (~8 seconds). Well
   inside the **D-Y** 15-minute warm-run ceiling, with room to
   absorb the remaining 65+ rows.

### Row-4 operation-keyed response shape — finding

The legacy `CheckResourcesResponse.decision` field is documented in
the parity contract's Summary Table as `Map<String, Set<String>>`.
The base-endpoint slice goldens confirm the **keying direction** is
`Map<operation, Set<id>>`, not `Map<id, Set<operation>>`. Specifically:

```text
{"DELETE":["row4-A"],"READ":["row4-A"],"WRITE":[]}
```

for a single request entry `{id: "row4-A", operations:
["READ","WRITE","DELETE"]}`. Every operation in the request appears
as a top-level key in the response; its value is the set of request
ids that were granted that operation (empty set when no id passed).
This shape is what Step 4 must reproduce from the Authz Agent
canonical decision set; Row 4 / Row 8 / Row 9 of the parity contract
should be annotated with this observation so the Step 4 executor does
not reinvent the mapping direction.

### Remaining Phase 4 work (deferred to later sessions)

The **fixture-dependent slice** of Phase 4 covers the other 65 rows
of the Planned Test Catalogue:

- **PSUITE-* rows 12–48** — validation + OLS/RLS sub-variants +
  TOKEN/HEADER/GENERAL-PIP coverage + multi-role + isolation +
  on-behalf-of (`userId` query param) + anonymous-allow-via-global
  row. These need the Phase 3 fixture-pack slice (expanded
  simplified-policy + PIP fixtures under `seed/policies/suite/`).
- **CLANG rows 49–60** — condition-language operator coverage.
  Gated on **OQ-SUITE-6** (legacy condition-evaluator grammar).
- **AGG rows 61–67** — policy aggregation / combining. Gated on
  **OQ-SUITE-8** (legacy rule-aggregator shape).
- **SUB rows 68–75** — predicate-template substitution. Gated on
  **OQ-SUITE-9** (legacy renderer escaping rules).
- **ENT rows 76–83** — entitlements AST. Gated on the
  `entitlements-mock` pinning templates (Phase 3 fixture-pack slice
  item 9).

### File manifest (Phase 4 + 5 + 6 base-endpoint slice, 2026-04-14)

| File                                                               | Change                                | Role                                                 |
| ------------------------------------------------------------------ | ------------------------------------- | ---------------------------------------------------- |
| `tests/parity/compose/idp-seed/parity-realm.json`                  | 5 user passwords + 5 user `id` fields | Uniform `ParityPass1!@#`; pinned UUIDs for stability |
| `tests/parity/scripts/smoke.sh`                                    | parity-reader password literal        | Aligned with realm uniform password                  |
| `tests/parity/suite/config.go`                                     | 3 default strings                     | M2M + end-user secrets + end-user password           |
| `tests/parity/suite/test_row01_api_version_test.go`                | new (~20 lines)                       | Row 1 golden                                         |
| `tests/parity/suite/test_row02_check_resource_v1_test.go`          | new (~170 lines)                      | Row 2 × 5 sub-cases                                  |
| `tests/parity/suite/test_row03_check_resource_bulk_v1_test.go`     | new (~50 lines)                       | Row 3 mixed                                          |
| `tests/parity/suite/test_row04_check_resource_bulk_ops_v1_test.go` | new (~45 lines)                       | Row 4 mixed                                          |
| `tests/parity/suite/test_row05_preview_bulk_ops_v1_test.go`        | new (~40 lines)                       | Row 5 mixed                                          |
| `tests/parity/suite/test_row06_check_filter_v1_test.go`            | new (~35 lines)                       | Row 6 rls-happy                                      |
| `tests/parity/suite/test_row07_check_resource_v2_test.go`          | new (~65 lines)                       | Row 7 × 2 sub-cases                                  |
| `tests/parity/suite/test_row08_check_resource_bulk_ops_v2_test.go` | new (~45 lines)                       | Row 8 mixed                                          |
| `tests/parity/suite/test_row09_preview_bulk_ops_v2_test.go`        | new (~40 lines)                       | Row 9 mixed                                          |
| `tests/parity/suite/test_row10_check_filter_v2_test.go`            | new (~35 lines)                       | Row 10 rls-happy                                     |
| `tests/parity/suite/test_row11_validation_missing_op_test.go`      | new (~50 lines)                       | Row 11 HTTP 400                                      |
| `tests/parity/suite/test_row16_validation_duplicate_ids_test.go`   | new (~45 lines)                       | Row 16 HTTP 400                                      |
| `tests/parity/suite/test_row29_validation_missing_rt_test.go`      | new (~35 lines)                       | Row 29 HTTP 400                                      |
| `tests/parity/suite/testdata/golden/**`                            | 15 new JSON files                     | Phase 5 goldens                                      |
| `tests/parity/scripts/run-parity-suite.sh`                         | new (~85 lines)                       | Phase 6 runner                                       |

**Total Phase 4+5+6 base-endpoint slice diff:** 18 files added,
3 files edited, ~900 lines added, ~15 golden JSON files
committed. No existing test file rewritten, no helper layer
touched.

### Next-session starting point (Phase 4 fixture-dependent slice)

1. Land the Phase 3 fixture-pack slice (expanded seed fixtures +
   `seed-access-control.sh` extension).
2. Start Phase 4 fixture-dependent slice by adding PSUITE-* rows
   12–48 first (OLS/RLS + PIP coverage + multi-role / isolation);
   these use the fixture pack but no new AST feature.
3. Resolve OQ-SUITE-6 and author CLANG rows 49–60.
4. Resolve OQ-SUITE-8 and author AGG rows 61–67.
5. Resolve OQ-SUITE-9 and author SUB rows 68–75.
6. Author ENT rows 76–83 once the entitlements-mock pinning
   templates are clean.
7. Re-run `run-parity-suite.sh` in record mode, inspect any new
   goldens, commit them, re-run without record mode, confirm
   `Parity suite passed: N/N cases green.` where N = 83 + any
   sub-case expansion per **D-X**.

### Phase 3 — Fixture-pack slice (partial, 2026-04-14)

Phase 3 fixture-pack work was started this session and stopped at the
point the combined policies PUT was about to hit the legacy server —
the user requested a hand-off checkpoint before the load was verified
end-to-end. The OQ research block is closed, the fixture-pack draft
is committed under `tests/parity/compose/seed/policies/suite/`, the
`seed-access-control.sh` extension is committed, and the PIPs PUT was
**manually verified green (HTTP 201)** against the running legacy
stack. The policies PUT has **not** yet been attempted — it is the
immediate next step for the follow-up session.

### OQ-SUITE-6/8/9 resolution (delegated research, closed)

1. **OQ-SUITE-6 — CLANG grammar (RESOLVED).** The authoritative
   source is the ANTLR grammar file
   `AbacExpression.g4`
   under the legacy policy-decision-point module. Verified token and
   parser rules:
   - **Equality:** `==`, `=`, or the word keyword `EQUALS`. All three
     accepted.
   - **Inequality:** `!=`, or `NOT EQUALS`.
   - **Numeric relational:** `>`, `>=`, `<`, `<=`, or word forms
     `GREATER THAN`, `GREATER THAN OR EQUAL TO`, `LESS THAN`,
     `LESS THAN OR EQUAL TO`.
   - **Containment:** `CONTAINS` (single-element), `CONTAINS ANY`
     (set intersection). There is **no** `CONTAINS ALL` in the
     grammar — use `IS SUBSET` / `IS NOT SUBSET` instead (verified
     against the `subsetOperator` rule).
   - **Set membership:** `IN`. Right-hand side is a comma-separated
     `LIST_OF_QUOTED_STRINGS` / `LIST_OF_NUMBERS` / multiple
     operand. Legacy test data confirms the literal form is a
     bare comma-separated list with single-quoted strings, **no**
     enclosing brackets or parens: `subject.roles CONTAINS ANY 'ROLE_TENANT-ADMIN', 'ROLE_CONTENT-MANAGER'`
     (policySetData.json:28-29).
   - **Boolean combinators:** `AND`, `OR`, `NOT` — all uppercase,
     space-separated. Operator precedence is `NOT` > `AND` > `OR`
     (from the grammar's `or` → `and` → `condition` recursion).
     Parentheses are **not** in the grammar — precedence is the
     only grouping tool.
   - **Null handling:** `X IS NULL`, `X IS NOT NULL`.
   - **Emptiness:** `X IS EMPTY`, `X IS NOT EMPTY`.
   - **String literals:** single quotes only (`fragment Quote: '\''`).
     Double-quoted strings are a parse error.
   - **Subject attribute access:** dot notation
     (`subject.department`, `subject.parityMeta.department`).
   The Phase 3 CLANG fixtures (`clang-string-equality.json`,
   `clang-number-relational.json`, `clang-boolean-or.json`,
   `clang-in-literal.json`, `clang-contains-any.json`,
   `clang-null.json`) use only verified-accepted spellings. Row 57
   (`CLANG-contains-all`) was replaced with an `IS SUBSET` variant
   per the grammar's actual operator set. Row 53 (`CLANG-not`) was
   rewritten to `resource.archived != true` because `NOT (expr)`
   with parentheses is not in the grammar.
2. **OQ-SUITE-8 — AGG combining shape (RESOLVED).** The
   combining algorithm runs at policy-level via
   `CombiningAlgorithm` (typically `DENY_UNLESS_PERMIT`). Multiple
   matching rules are **not** merged into a single rule — each
   rule is evaluated independently and the builder at
   `EvaluationResultBuilder.java:72-93`
   assembles the final result:
   - Unconditional OLS rule that permits → `calcResult = Effect.ALLOW`
     and `filterCondition = null`. A subsequent RLS rule's
     `rsqlPredicate` is **absorbed** and does not appear in the
     response.
   - All-RLS match → `calcResult = USE_FILTER_CONDITION` with the
     matching rules' predicates **OR-joined** into the response's
     `rsqlFilterCondition` / other predicate fields.
   - No match → `calcResult = NOT_APPLICABLE`.
   Phase 3 AGG fixtures (`rls-agg-two-predicates.json`,
   `rls-agg-ols-plus-rls.json`, `ols-multi-role.json`) are designed
   around this finding — row 64 is seeded as a deliberate
   OLS-absorbs-RLS case, row 63 seeds two RLS rows on the same
   locator so the engine OR-joins their predicates.
3. **OQ-SUITE-9 — SUB template substitution (PARTIALLY RESOLVED;
   reached a simplified-policy constraint instead).** The `${subject.<alias>}`
   template substitution mechanism is real and server-side — the
   legacy test data at
   `00005/policySetData.json:193`
   uses `"sqlPredicate": "resource.id IN (${subject.dataFromHeaderPip})"`
   and the existing Step 2 `general-pip.json` fixture already uses
   `"rsqlPredicate": "id=in=(${subject.parityAllowed})"` (verified
   green in Phase 4 base-endpoint slice). The concrete renderer
   symbol was not pinned down by the research agent — the grammar
   transformer at
   `ConditionTransformer.java:26-34`
   only handles the `condition` AST field; predicate-template
   substitution lives elsewhere (likely in the simplified-policy
   loader service that converts a simplified row into a full policy
   before it reaches the evaluator). Locating the exact renderer
   is deferred until a SUB row actually disagrees with expectations
   — the rsqlPredicate-only SUB row in the fixture pack
   (`rls-general-scalar.json`) gives the end-to-end path enough
   coverage that Phase 4 goldens will either confirm or deny the
   assumption empirically.
4. **Simplified-policy field-set constraint (NEW FINDING).** The
   simplified-policy input DTO
   `BaseSimplifiedPolicy.java`
   has **only** `condition` and `rsqlPredicate` as predicate-carrying
   input fields. There is no `sqlPredicate` / `mongodbPredicate`
   input — the `sqlFilterCondition` and `mongodbFilterCondition`
   fields the parity response carries are populated by a different
   (full-policy / XACML) code path that the simplified-policy
   channel cannot reach. Consequences for the Planned Test Catalogue:
   - **SUB row 71** (scalar into `sqlFilterCondition`) — not
     writeable as a simplified-policy fixture.
   - **SUB row 72** (scalar into `mongodbFilterCondition`) — not
     writeable.
   - **SUB row 73** (array into `sqlFilterCondition`) — not
     writeable.
   - **Row 22** (PSUITE-6-use-filter-incoming: all four predicate
     types populated) — not writeable via simplified-policy.
   Historical note: these rows were explicit gaps at this point in the
   third session. The fourth session closed them by adding the regular
   full-policy import pass to `seed-access-control.sh`; see
   [§Follow-ups opened in the third session](#follow-ups-opened-in-the-third-session).

### Implemented changes (Phase 3 fixture-pack slice, partial)

1. **New directory `tests/parity/compose/seed/policies/suite/`** with
   an inline `README.md` that cross-references the grammar file, the
   legacy test-data exemplars, and the simplified-policy field-set
   constraint. The README is the authoritative reference sheet for
   anyone extending the fixture pack later.
2. **PIP declarations** — `suite/suite-pips.json` adds five PIP rows
   on top of the Step 2 `general-pip-pips.json`:
   - `subject.parityDepartment` — TOKEN PIP on JWT claim `department`.
   - `subject.parityTier` — TOKEN PIP on JWT claim `tier`.
   - `subject.parityHeaderAttr` — HEADER PIP on `x-parity-pip-attribute`.
   - `subject.parityMeta` — GENERAL PIP with `type=JSON`, `jsonPath=$`
     at `http://pip-mock:8090/api/v1/pip/meta`. Returns the entire
     mock body so condition ASTs can walk nested fields
     (`subject.parityMeta.department`).
   - `subject.parityStatusScalar` — GENERAL PIP with `type=JSON`,
     `jsonPath=$.value` at `http://pip-mock:8090/api/v1/pip/status-scalar`.
     Mock body is `{"value":"OPEN"}` and the jsonPath extracts the
     inner string for template substitution.
   **Validated end-to-end** via a manual PUT to
   `http://localhost:28090/access/v1/simplifiedPolicies/domainPIPs/PARITY?tenant_id=default`
   using a fresh M2M bearer — returned **HTTP 201** with the
   full JSON body echoed back. The PIP pack is accepted by the
   legacy validator.
3. **OLS / RLS fixtures** — 10 new simplified-policy files under
   `suite/`, one per scenario class:
   - `ols-multi-role.json` — two OLS rows on
     `(PARITY_SUITE_MULTI, READ)` with distinct roles.
   - `rls-token-pip.json` — `subject.parityDepartment == 'finance'`
     on `(PARITY_SUITE_TOKEN, READ)`.
   - `rls-header-pip.json` — `subject.parityHeaderAttr == 'parity-allow'`
     on `(PARITY_SUITE_HEADER, READ)`.
   - `rls-general-dict.json` — `resource.department == subject.parityMeta.department`
     on `(PARITY_SUITE_DICT, READ)`.
   - `rls-general-scalar.json` — `rsqlPredicate: "status==${subject.parityStatusScalar}"`
     on `(PARITY_SUITE_SCALAR, LIST)` (SUB row 68).
   - `rls-agg-two-predicates.json` — two RLS rows on
     `(PARITY_SUITE_AGG_PRED, LIST)` with different rsqlPredicate
     templates (AGG row 63).
   - `rls-agg-ols-plus-rls.json` — one OLS + one RLS row on
     `(PARITY_SUITE_AGG_MIXED, LIST)` (AGG row 64).
   - `rls-allow.json` — pure-OLS baseline on
     `(PARITY_SUITE_ALLOW, LIST)` (row 21 `calcResult=ALLOW`).
   - `clang-string-equality.json`, `clang-number-relational.json`,
     `clang-boolean-or.json`, `clang-in-literal.json`,
     `clang-contains-any.json`, `clang-null.json` — six CLANG
     fixtures using verified spellings (rows 49, 50, 52, 54, 56, 58).
4. **Seed script extension** —
   `tests/parity/compose/seed/scripts/seed-access-control.sh`
   rewritten to merge every Step 2 + `suite/*.json` file into a
   single PUT payload per collection (policies and PIPs
   separately). The jq expansion preserves the PIP-before-policy
   ordering discipline from Step 2 and explicitly excludes
   `suite/suite-pips.json` from the policies pass and
   `suite/README.md` from the jq glob.

### Validation performed (Phase 3 fixture-pack slice, partial)

1. **PIPs PUT against live stack** — manual curl from the host with
   a fresh `parity-m2m` client-credentials bearer. Response: HTTP
   201 Created with the full PIP pack echoed. This confirms:
   - The `jsonPath` fix for `type=JSON` PIPs
     (`PolicyInformationPointValidator.java:266-282`) is correct —
     the first draft without jsonPath was rejected HTTP 400 with
     `'jsonPath' parameter cannot be empty for JSON return type`.
   - The TOKEN / HEADER / GENERAL combinations all pass the legacy
     validator.
2. **Policies PUT — NOT YET ATTEMPTED.** The user paused the
   session at the point the combined-policies PUT was about to run.
   The follow-up session picks up exactly there.
3. **`smoke.sh` — NOT YET RE-RUN** against the new seed. Will run
   as part of the follow-up session's validation pass, before and
   after the first green policies PUT.
4. **Go test suite — NOT YET RE-RUN** against the new seed. Phase
   4 fixture-dependent slice is still pending.

### Remaining Phase 3 work (next session, tight scope)

1. **Attempt the combined policies PUT.** Run:

   ```text
   jq -s 'add | map(del(._comment))' \
     tests/parity/compose/seed/policies/{ols-allow,ols-deny,rls-filter,general-pip}.json \
     tests/parity/compose/seed/policies/suite/{ols-multi-role,rls-token-pip,rls-header-pip,rls-general-dict,rls-general-scalar,rls-agg-two-predicates,rls-agg-ols-plus-rls,rls-allow,clang-string-equality,clang-number-relational,clang-boolean-or,clang-in-literal,clang-contains-any,clang-null}.json \
     > /tmp/pol.json
   curl -sSf -X PUT \
     -H "Authorization: Bearer $M2M" \
     -H "Content-Type: application/json" \
     --data-binary @/tmp/pol.json \
     "http://localhost:28090/access/v1/simplifiedPolicies/domainPolicies/PARITY?tenant_id=default"
   ```

   and inspect the response. If the legacy validator rejects any
   row with HTTP 400, diagnose by splitting the payload: PUT the
   Step 2 fixtures alone first, confirm HTTP 201, then add one
   suite file at a time until the failing row is isolated. The
   fixture files are intentionally small (1–2 rows each) so this
   bisection is cheap.
2. **Bring up a clean stack** via
   `docker compose -f tests/parity/compose/docker-compose.yml down -v`
   - `up -d` and confirm `parity-ac-seed` exits 0 on its own
   (no manual PUTs needed). This proves the seed script extension
   is idempotent and self-contained.
3. **Run `smoke.sh` against the new seed** — expected `Smoke run
   passed: 12/12 checks green.` unchanged. Record both
   observations in the Execution Report per **D-H**.
4. **Skip to Phase 4 fixture-dependent slice** — the golden test
   grind.

### File manifest (Phase 3 fixture-pack slice, partial)

| File                                                                    | Change             | Role                                                   |
| ----------------------------------------------------------------------- | ------------------ | ------------------------------------------------------ |
| `tests/parity/compose/seed/policies/suite/README.md`                    | new                | Grammar reference sheet + file layout + constraints    |
| `tests/parity/compose/seed/policies/suite/suite-pips.json`              | new                | TOKEN/HEADER/GENERAL PIP declarations (5 rows)         |
| `tests/parity/compose/seed/policies/suite/ols-multi-role.json`          | new                | AGG 61/62 multi-role OLS pair                          |
| `tests/parity/compose/seed/policies/suite/rls-token-pip.json`           | new                | TOKEN-PIP RLS row (condition reads JWT claim)          |
| `tests/parity/compose/seed/policies/suite/rls-header-pip.json`          | new                | HEADER-PIP RLS row (condition reads custom header)     |
| `tests/parity/compose/seed/policies/suite/rls-general-dict.json`        | new                | GENERAL-PIP dict-return RLS row (nested-field compare) |
| `tests/parity/compose/seed/policies/suite/rls-general-scalar.json`      | new                | SUB row 68 (rsqlPredicate template substitution)       |
| `tests/parity/compose/seed/policies/suite/rls-agg-two-predicates.json`  | new                | AGG row 63 (two RLS rows, predicate OR-join)           |
| `tests/parity/compose/seed/policies/suite/rls-agg-ols-plus-rls.json`    | new                | AGG row 64 (OLS + RLS on same locator)                 |
| `tests/parity/compose/seed/policies/suite/rls-allow.json`               | new                | Row 21 baseline (pure OLS ALLOW)                       |
| `tests/parity/compose/seed/policies/suite/clang-string-equality.json`   | new                | CLANG row 49                                           |
| `tests/parity/compose/seed/policies/suite/clang-number-relational.json` | new                | CLANG row 50                                           |
| `tests/parity/compose/seed/policies/suite/clang-boolean-or.json`        | new                | CLANG row 52                                           |
| `tests/parity/compose/seed/policies/suite/clang-in-literal.json`        | new                | CLANG row 54                                           |
| `tests/parity/compose/seed/policies/suite/clang-contains-any.json`      | new                | CLANG row 56                                           |
| `tests/parity/compose/seed/policies/suite/clang-null.json`              | new                | CLANG row 58                                           |
| `tests/parity/compose/seed/scripts/seed-access-control.sh`              | edited (~30 lines) | jq expansion loads suite/*.json alongside Step 2 files |

**Total Phase 3 fixture-pack slice diff:** 1 directory + 16 files
added, 1 file edited, ~320 lines added. No existing Step 2 file
touched.

### Follow-ups opened in the third session

- **OQ-SUITE-12 — full-policy PUT channel needed. Closed in the fourth
  session.** `seed-access-control.sh` now imports
  `tests/parity/compose/seed/policies/regular/parity-suite-full.json`
  through `PUT /access/v1/policySets/externalId/{externalId}`. This
  closes PSUITE row 22 and SUB rows 71/72/73 on the legacy stack.
- **OQ-SUITE-13 — SUB renderer symbol.** The exact legacy symbol
  responsible for `${subject.<alias>}` template substitution was not
  pinned down during OQ-SUITE-9 research. The behavior is
  empirically known to work (Step 2 fixture + row 2 general-pip-allow
  golden), but the renderer file:line is missing from the Transport
  Convention Inventory. Low priority — track until a SUB row
  misbehaves.
- **OQ-SUITE-14 — Netcracker Keycloak image has a time-based
  license expiry that kicks in ~30 minutes after IdP start.**
  Symptom: `POST /auth/realms/parity/protocol/openid-connect/token`
  returns HTTP 403 with body `{"message":"License expired!"}`
  even for well-formed `client_credentials` grants, and nothing
  in the IdP logs points at the license check. Workaround:
  `docker compose -f tests/parity/compose/docker-compose.yml
  restart idp` — IdP comes back healthy in ~15 s and token mint
  resumes. This contradicts the docker-compose.yml comment at
  line ~71 ("Keycloak-level licensing is disabled by pointing at a
  bogus in-network URL that never resolves (the SPI only checks
  it when an admin op is attempted)"); either the SPI is actually
  checking during normal token flow, or a separate SPI is
  running the 30-min expiry. **Impact on Phase 7 stability gate:**
  `run-parity-suite.sh` must complete the full suite in under
  ~25 minutes wall-clock before IdP needs a kick, or the script
  needs to restart the IdP before starting the Go suite. The
  base-endpoint slice runs in ~2 s of Go test time so there is
  no practical risk yet, but the fixture-dependent slice (~65
  additional rows) has to be watched. Track as **OQ-SUITE-14**
  and re-evaluate after the first end-to-end run with the full
  suite.

### Phase 3 — Fixture-pack slice follow-up attempt (paused, 2026-04-14 second session)

Second session of the same day picked up where the first stopped
(the combined policies PUT was about to be attempted). Paused again
at the user's request before the PUT actually landed; the diagnostics
gathered in between are recorded below so the next executor can
resume without re-running them.

### What happened this session

1. **Stack was still running from the first session** (30+ minutes
   uptime). Token-mint-via-smoke.sh-step-[2/12] returned
   `{"message":"License expired!"}` with HTTP 403 — the Netcracker
   IdP image has an undocumented lazy license check that kicks in
   after ~30 minutes of uptime. **This is a new finding recorded as
   OQ-SUITE-14 above.**
2. **IdP restart reset the license state.** `docker compose restart
   idp` brought the container back healthy in ~15 s; a direct
   `client_credentials` token mint succeeded immediately afterward
   with a well-formed `access_token`.
3. **smoke.sh was re-run post-restart.** Steps [1/12]–[4/12] passed
   (api-version, both token mints, pip-mock reset). **Step [5/12]
   (`PARITY_CUSTOMER READ` OLS allow) FAILED** with `expected 'true',
   got 'false'`. This is a **regression on a path that was 12/12
   green in the first session** — and it is NOT caused by a fixture
   edit (ols-allow.json is Step 2's untouched smoke fixture).
4. **AC logs at `[2026-04-14T13:25:32]`** show
   `UPDATE_SIMPLIFIED_PIPS|Simplified PIPs configuration by domain
   was updated` followed by
   `caches evicted successfully [tenants, effectivePolicies,
   effectivePIPs, permissions, policySets, policies, executors,
   rules, policyInformationPoints]`. That is the successful manual
   PIPs PUT from the first session. **Note:** the `domainPIPs` PUT
   has replace-all semantics — the manual PUT pushed the combined
   (Step 2 + suite) PIP pack and the Step 2 `subject.parityAllowed`
   PIP was preserved in the jq merge. So the failing
   `check/resource` is not explained by a missing PIP.
5. **Two earlier error lines** at `[2026-04-14T13:05:35]` and
   `[2026-04-14T13:24:18]`:
   `PIP subject.parityMeta cannot be created due to configuration
   error: 'jsonPath' parameter cannot be empty for JSON return type
   for PIP 'subject.parityMeta'`.
   These are from the **failed initial ac-seed PUT** (before my
   in-session jsonPath fix). They stopped after the manual PIPs PUT
   at 13:25:32, confirming the fix landed.
6. **The contamination hypothesis.** The stack is in a
   partial-seed state: its `domainPIPs` carry my new
   suite-pips.json pack (valid), but its `domainPolicies` still
   carry only the Step 2 four fixtures from the first-session cold
   boot. Yet `ols-allow` is suddenly returning `false`. Possible
   causes:
   - The `CacheEvictSynchronization` line suggests the policy
     cache was flushed when the PIP PUT ran. On the next request,
     the evaluator would re-load policies from DB. If the DB
     state is consistent with the Step 2 seed, OLS allow should
     still pass — unless the legacy engine now **requires** every
     referenced PIP to be reachable at evaluation time, and one of
     the new PIPs (`subject.parityMeta` with a URL that probably
     returns pip-stub's 404 fallback) is poisoning the per-request
     subject context.
   - Or the OLS evaluation path reads *all* declared PIPs into
     `subject.*` at request start time, and if any PIP fails its
     HTTP round-trip, the entire subject is marked tainted.
   - Or `[2026-04-14T13:38:07] audit enabled: 'false'` indicates
     a config change that toggled something.
   The cleanest next step is a full `down -v` + `up -d` —
   destroying the mixed state entirely and letting the extended
   `seed-access-control.sh` do its job from a clean slate. If the
   new seed script still fails, the ac-seed exit code + logs will
   show exactly which PUT fails, and the bisection workflow
   described in the first session's "Remaining Phase 3 work"
   bullet list applies verbatim.

### Next-session recipe (tight)

1. **Go straight to a full cold reset:**

   ```text
   docker compose -f tests/parity/compose/docker-compose.yml down -v
   docker compose -f tests/parity/compose/docker-compose.yml up -d
   ```

2. **Wait for every service healthy + `parity-ac-seed` exit code**
   (the ready probe from the earlier `bu9k6u2nw`-style loop is a
   good template). If `ac-seed` exits 0, the extended seed script
   handled both PIPs and policies cleanly and you can move to
   step 4.
3. **If `ac-seed` exits 22 (curl HTTP 4xx/5xx):** `docker logs
   parity-ac-seed` shows the failing PUT and the legacy error
   body. The combined payload is built by the script itself —
   reproduce locally with the same `jq -s ...` expression to
   isolate the offending file, then bisect by dropping suite/*.json
   files one at a time. The fixture pack is 14 files; bisection is
   ≤4 iterations.
4. **Run `smoke.sh`** against the new seed:
   `bash tests/parity/scripts/smoke.sh`.
   Expected: `Smoke run passed: 12/12 checks green.` If step [5/12]
   fails on OLS allow again, the regression is reproducible on a
   clean stack and the bug is in the way the expanded PIP set
   interacts with legacy AC's subject pre-loading — at that point
   check whether `pip-mock` is returning a default 404 for the
   new paths (`/api/v1/pip/meta`, `/api/v1/pip/status-scalar`)
   and whether that 404 poisons the subject.
5. **Run `tests/parity/scripts/run-parity-suite.sh`** —
   expected to still print
   `Parity suite passed: 18/18 cases green.` for the
   base-endpoint slice. If it regresses, the 18 base-endpoint
   tests and the 15 committed goldens are the first-line debug
   anchor: every base-endpoint test uses only Step 2 fixtures, so
   a failure there points at a cross-contamination from the
   expanded PIP set.
6. **Only after smoke + base-endpoint suite are green on the new
   seed**, move to writing Phase 4 fixture-dependent tests.

### State of the working tree at pause

- All 16 fixture-pack files + the seed script edit + the handover
  updates are committed to the working tree (not staged, not
  committed to git). `git status` still shows them as `??` / `M`
  respectively.
- The running Compose stack is in the partial state described in
  step 6 above: new PIPs, old policies, OLS allow broken. It is
  **safe to tear down** — nothing in it is load-bearing for any
  other task.
- The Go module under `tests/parity/suite/` is unchanged since
  the base-endpoint slice close. All 18 Phase 4 tests compile and
  should still pass against a fresh seed that preserves
  backwards-compatibility on the Step 2 resource types.

### Handover note for the next agent

The work remaining on this task is **mechanical grinding** more
than it is design. The hard questions (OQ-SUITE-6/8/9/10/11) are
answered, the grammar is inventoried, the infrastructure is in
place, and the base-endpoint slice is proven green. What is left
is:

1. Prove the extended seed script loads cleanly on a fresh stack
   (1–2 hours including debug loops).
2. Prove `smoke.sh` stays 12/12 green against the extended seed
   (< 10 minutes).
3. Author ~65 additional testify tests mapped one-per-catalogue-row
   for the fixture-dependent slice (PSUITE-* rows 12–48 + CLANG +
   AGG + SUB + ENT). Most of them are copy-paste variants of the
   18 base-endpoint tests already in the tree; ENT is the only
   block that needs new `PipController.PinEntitlementsV3ForUser`
   calls in `SetupTest` (the helper already exists in `pip_control.go`).
4. Record goldens via `PARITY_GOLDEN_RECORD=1`, inspect, commit,
   stability-check (zero diff on second run).
5. Update this handover's `Done` checklist and fill the Execution
   Report numbers (wall-clock, golden count, test count).

None of those steps requires a new architectural decision. The
paragraph above is now historical only: the fourth session closed
OQ-SUITE-12 by adding the regular full-policy seed import, so those
rows are no longer a parity gap.

### Phase 3 + 4 continuation (2026-04-14 third session)

Third session of the same day resumed from the second-session pause
state above. This session **closed the Phase 3 seed blocker** and
advanced the fixture-dependent Go suite beyond the 18-case
base-endpoint slice.

### What happened

1. **Reproduced the Phase 3 seed failure on a clean stack.**
   `docker compose down -v && up -d` was re-run first. The stack
   came up cleanly through `parity-access-control healthy`, but
   `parity-ac-seed` exited `22`. Logs showed PIPs PUT succeeded and
   the failure was the combined `domainPolicies` PUT returning HTTP
   400.
2. **Isolated the exact legacy validator error.** Manual repro of the
   same combined policies payload against
   `/access/v1/simplifiedPolicies/domainPolicies/PARITY` returned:
   `Expression [resource.department == subject.parityMeta.department]:
   Invalid expression: subject.parityMeta.department PIP doesn't exist`.
   This pinned the failure to the dict-return GENERAL-PIP fixture
   `rls-general-dict.json`, not to the seed script plumbing.
3. **Closed OQ-SUITE-15 in-place.**
   Evidence:
   - `ConditionTransformer.ConditionVisitor.getPolicyInformationPoint(...)`
     looks up only a direct PIP name from the grammar token and raises
     `%s PIP doesn't exist` when no exact alias is registered.
   - Legacy PIP docs under
     `documentation/development-guide/policy-information-point/README.md`
     explicitly position `jsonPath` as the supported mechanism for
     extracting a string / number / array leaf from a JSON-returning
     GENERAL PIP.
   Resolution:
   - `suite-pips.json` now models the dict-return scenario through
     direct leaf aliases:
     `subject.parityMetaDepartment`, `subject.parityMetaMaxAmount`,
     `subject.parityMetaIds`.
   - `rls-general-dict.json` now references those aliases directly:
     `resource.department == subject.parityMetaDepartment AND resource.amount <= subject.parityMetaMaxAmount`.
   - `tests/parity/compose/seed/policies/suite/README.md` was updated
     to document the legacy-validator constraint.
4. **Re-validated Phase 3 end-to-end after the leaf-alias fix.**
   - Manual host-side combined PIPs PUT: HTTP `201`.
   - Manual host-side combined policies PUT: HTTP `200`.
   - Fresh `docker compose down -v && up -d`: `parity-ac-seed`
     reached `exited:0`.
   - `bash tests/parity/scripts/smoke.sh`: `Smoke run passed: 12/12 checks green.`
5. **Extended the Phase 4 Go suite with fixture-dependent slices.**
   New helper + test files landed:
   - `tests/parity/suite/suite_case_helpers_test.go`
   - `tests/parity/suite/test_row02_fixture_cases_test.go`
   - `tests/parity/suite/test_row06_fixture_cases_test.go`
   - `tests/parity/suite/test_row07_fixture_cases_test.go`
   Coverage added in this session:
   - Row 2: TOKEN-PIP, HEADER-PIP, GENERAL JSON-leaf dict path,
     AGG multi-role, CLANG string/number/or/in/contains-any/null.
   - Row 6: pure-allow baseline, AGG two-predicate union,
     AGG OLS+RLS, SUB scalar GENERAL-PIP substitution.
   - Row 7: TOKEN-PIP, HEADER-PIP, GENERAL list, GENERAL JSON-leaf
     dict path, AGG multi-role.
6. **Recorded and stability-checked new goldens.**
   - Record-mode targeted runs (`PARITY_GOLDEN_RECORD=1`) captured the
     new goldens under:
     `testdata/golden/check-resource-v1/`,
     `testdata/golden/check-filter-v1/`,
     `testdata/golden/check-resource-v2/`.
   - A first full non-record `run-parity-suite.sh` surfaced one
     stability issue: row-7 GENERAL-PIP-list allow depended on a
     PIP allow-set that drifted across earlier suite calls. The test
     was fixed to reuse the same allow-set ids as the established row-2
     GENERAL-PIP cases (`row2-pip-allow`, `row2-pip-other`), which
     matches the observed legacy caching behavior and stabilizes the
     v2 list row inside the full suite.
   - Second full non-record `run-parity-suite.sh` passed cleanly.

### Validation performed (fourth session)

1. `docker compose -f tests/parity/compose/docker-compose.yml up -d --force-recreate ac-seed`
   Result: `parity-ac-seed` reached `exited:0` after removing the unsupported
   prohibited-header PIP and after adding the regular full-policy import pass.
2. `PARITY_GOLDEN_RECORD=1 bash tests/parity/scripts/run-parity-suite.sh`
   Result: record-mode suite green on the full catalogue, goldens written.
3. `go build -tags integration ./...`
4. `go vet -tags integration ./...`
   Results: both exited `0`.
5. `bash tests/parity/scripts/run-parity-suite.sh`
   Result: `Parity suite passed: 130/130 cases green.`
6. Second consecutive non-record run:
   `bash tests/parity/scripts/run-parity-suite.sh`
   Result: `Parity suite passed: 130/130 cases green.`
7. Pre-closure cold/warm timing capture:
   - cold `run-parity-suite.sh` after `docker compose down -v`: `49.45s`
   - warm `run-parity-suite.sh`: `1.47s`
8. `find tests/parity/suite/testdata/golden -name '*.observed.json'`
   Result: `0` files.
9. `git commit -m "tests/parity: close parity suite follow-ups"`
   Result: commit `98b5520` contains the Step 3 suite/golden/fixture/runtime
   artefacts in committed state.
10. Post-commit cold verification:
    `docker compose -f tests/parity/compose/docker-compose.yml down -v && /usr/bin/time -f 'elapsed_seconds=%e' bash tests/parity/scripts/run-parity-suite.sh`
    Result: `Parity suite passed: 130/130 cases green.` in `53.24s`.
11. Post-commit warm verification:
    `/usr/bin/time -f 'elapsed_seconds=%e' bash tests/parity/scripts/run-parity-suite.sh`
    Result: `Parity suite passed: 130/130 cases green.` in `5.64s`.
12. `git status --short tests/parity/suite/testdata/golden`
    Result: no output (golden tree clean in committed state).
13. `rg -n '83/83|83 cases' docs/handovers/20260414-access-control-parity-test-suite-task.md docs/handovers/20260414-access-control-parity-test-suite-task.prompt.md docs/plans/20260413-access-control-parity-testing-plan.md`
    Result: historical-context mentions only; no forward-looking `83/83`
    target remains.

### Current state after the fourth session

1. **Step 3 is complete on the legacy stack.**
   The seed pack now spans both simplified-policy and regular full-policy
   channels; the Go/testify suite covers all 83 catalogue rows.
2. **Current green suite footprint:** `130/130` leaf sub-cases across the
   83-row catalogue, with `127` golden JSON files recorded under
   `tests/parity/suite/testdata/golden/`.
3. **OQ-SUITE-12 is closed.**
   PSUITE row 22 and SUB rows 71/72/73 are now exercised through the
   regular full-policy seed imported by `seed-access-control.sh`.
4. **OQ-SUITE-14 remains informational only.**
   The observed cold (`49.45s`) and warm (`1.47s`) suite runtimes remain
   comfortably below the time window where the IdP license-expiry caveat has
   been observed.

### Follow-up closure (2026-04-14)

1. **Step 3 is now fully closed in committed state.**
   Landing commit `98b5520` put the suite, seed fixtures, runtime-script
   changes, and `127` golden JSON files into git.
2. **Post-commit stability re-verified after the F1 landing.**
   A fresh cold rerun completed in `53.24s`; the subsequent warm rerun
   completed in `5.64s`; both printed
   `Parity suite passed: 130/130 cases green.`.
3. **Committed-state hygiene is clean.**
   `git status --short tests/parity/suite/testdata/golden` is empty and
   `find tests/parity/suite/testdata/golden -name '*.observed.json'`
   still returns `0`.
4. **The formal Phase 7 blockers are closed.**
   F1 and O1–O5 are all checked off below, so Step 4 can now draft
   directly against the committed legacy baseline instead of the
   earlier working-tree snapshot.

### Next-session starting point (follow-up closure)

Step 4 can now be authored against the recorded legacy goldens: re-point the
same suite at Authz Agent, preserve the `130/130` leaf-case baseline, and
work down any divergences without re-recording the legacy answers.

> **No remaining Step 3 blockers.** The goldens and their consuming test files
> are committed, the post-commit cold/warm reruns are green, and the Phase 7
> close-out checklist below is fully checked.

### Validation follow-ups from Phase 3–6 review (2026-04-14)

Results from the post-Phase-6 validation pass. Closed on `2026-04-14`:
F1 landed in commit `98b5520`, the post-commit cold/warm reruns stayed
green, and O1–O5 were resolved. The checklist below remains as the
Phase 7 closure log in addition to the existing Done-list at the top of
this handover.

### F1 — Commit all Phase 3–6 artefacts (closed, **D-W point 2**)

Root cause: cold + warm `run-parity-suite.sh` both print
`Parity suite passed: 130/130 cases green.`, 0 `.observed.json`
sidecars after warm run, stability empirically holds — but 112 out of
127 golden JSON files and 17 out of ~29 new `test_row*_test.go` files
are still **untracked** in the working tree. Step 4 cannot re-assert
against a baseline that is not in git.

- [x] **F1.1** — `git add tests/parity/suite/testdata/golden && git status --porcelain tests/parity/suite/testdata/golden`
      returned zero `??` entries before the landing commit; after the commit
      the path is fully clean.
- [x] **F1.2** — `git add tests/parity/suite/test_row*_test.go` so every
      golden has a Go test that consumes it in the same commit. Landed in
      commit `98b5520`.
- [x] **F1.3** — `git add tests/parity/compose/seed/policies/suite/
      tests/parity/compose/seed/policies/regular/
      tests/parity/compose/seed/scripts/seed-access-control.sh` —
      fixtures and seed loader script that the Phase 3 extension adds.
- [x] **F1.4** — `git add` the remaining tracked-modified Phase 3 files
      surfaced by `git status --short tests/parity` (README, compare.go,
      model/entitlements.go, tokens.go, rls-general-dict.json,
      suite-pips.json, README bumps).
- [x] **F1.5** — After commit, re-run `bash tests/parity/scripts/run-parity-suite.sh`
      cold and warm, confirm both still print `130/130`, and confirm
      `git status --short tests/parity/suite/testdata/golden` is empty.
      This is the **D-W stability check against committed state**,
      which is what D-W point 4 actually requires. Verified post-commit:
      cold `53.24s`, warm `5.64s`, both green, golden tree clean.
- [x] **F1.6** — Commit the Execution Report update that records the
      F1 closure (commit SHA, wall-clock times of the post-commit
      verification runs). Recorded below; landing artefact commit is
      `98b5520`.

### O1 — Test-file naming divergence (low-priority cleanup)

Handover spec at iteration 7 Phase 2 Deliverables §1.3 expected the
following test-file names:

```text
tests/parity/suite/tests/
  condition_language_test.go   (CLANG, rows 49–60)
  policy_aggregation_test.go   (AGG, rows 61–67)
  predicate_substitution_test.go (SUB, rows 68–75)
  entitlements_test.go         (ENT, rows 76–83)
```

Phase 4 executor instead distributed CLANG / AGG / SUB / ENT content
across per-parity-row test files with suffixes (`test_row02_clang_additional_cases_test.go`,
`test_row02_agg_additional_cases_test.go`, `test_row02_entitlement_cases_test.go`,
etc.). Functionally equivalent — all 130 leaf sub-cases are green —
but diverges from the spec.

Resolution options:

1. **(a) Update the spec to match reality.** Rewrite Phase 2
   Deliverables §1.3 file-layout section to describe the per-row
   file-suffix convention Phase 4 actually landed. Add a short note
   explaining why per-row files work better than per-block files for
   this suite (CLANG/AGG/SUB/ENT rows share seed fixtures with
   PSUITE rows on the same parity-contract row, so co-locating
   them reduces context-switching when a fixture needs to be read
   against multiple tests).
2. **(b) Rename files to match the spec.** `git mv` the per-block
   content into the four block-level files, re-run the suite, confirm
   `130/130` holds, commit.

- [x] **O1.1 — Decision:** chose **(a)**, update the spec to match
      reality. The per-row layout is the better fit for how fixtures
      and tests co-evolve, and renaming 17 files would add churn
      without functional gain.
- [x] **O1.2** — Applied option (a): Phase 2 Deliverables, the prompt,
      and the file-layout examples now describe the per-row naming
      convention that actually landed.

### O2 — `s.Run` sub-test pattern alternative vs D-X literal

D-X originally described the leaf pattern only in terms of literal
`s.Run("<sub-case-name>", func() { ... })` calls. The landed suite uses
a mix of literal `s.Run(...)` table-driven leaves and dedicated
`func (s *ParitySuite) TestRow<N><Scenario>...()` methods on the Suite
type, both of which produce individually named leaf failures in
`go test -v` output.

Failure isolation — the D-X success metric — is **met** either way:
`FAIL: TestParitySuite/TestRow07CheckResourceV2GeneralPipDict/deny`
names the failing leaf directly. The golden-file layout
`testdata/golden/<endpoint>/<row>/<sub-case>.json` is also preserved
per **D-X** directory convention (127 goldens confirm it).

Resolution options:

1. **(a) Accept the alternative as D-X-equivalent.** Document in D-X
   that either literal `s.Run(...)` calls **or** per-sub-case
   `Test...()` methods on the Suite type satisfy the decision, as
   long as (i) failing leaves are individually named in `go test -v`
   output, and (ii) golden files live under the D-X directory
   convention. Both properties hold in the current tree.
2. **(b) Rewrite 17 test files to use literal `s.Run(...)`.** Lots of
   churn, zero functional change.

- [x] **O2.1 — Decision:** chose **(a)**. The goal is failure
      isolation and the current tree meets it; rewriting would add
      churn with no observable gain.
- [x] **O2.2** — D-X's "How to apply" paragraph now explicitly accepts
      both alternatives (literal `s.Run` OR per-sub-case Suite method),
      matching the landed suite.

### O3 — `83/83` vs `130/130` cosmetic counter framing

Earlier iterations referenced `Parity suite passed: 83/83 cases green.`
(row count). Phase 6 `run-parity-suite.sh` actually emits
`130/130` (leaf sub-case count via the awk-based leaf-walker). Plan
Handovers row, prompt delivery checklist, and handover Phase 6 text
were all updated by the executor in-flight to match the leaf-count
framing. No mismatch in any committed file; this is a bookkeeping
note only.

- [x] **O3.1** — Final proofread: `grep -nE '83/83|83 cases'` across
      `docs/handovers/20260414-access-control-parity-test-suite-task.md`,
      `docs/handovers/20260414-access-control-parity-test-suite-task.prompt.md`,
      and `docs/plans/20260413-access-control-parity-testing-plan.md`
      returns only historical-context mentions (count updates, iteration
      changelogs). No forward-looking `83/83` must remain as the target
      count — the target is now `130/130`.
- [x] **O3.2** — No forward-looking `83/83` target remained after the
      proofread, so no additional counter edit was needed beyond the
      closure bookkeeping recorded here.

### O4 — Step 2 IdP license-state expiration brittleness (runtime caveat)

Observed: after ~49 minutes of continuous `parity-idp` uptime, the
`RefreshLicenseStateFromLicensingServer` SPI (Step 2 **Follow-up 1.8 /
Gap 5.g**) stops returning refreshed license state, and
`parity-idp` starts failing every OIDC token request with HTTP 403
`{"message": "License expired!"}`. This is **not a Phase 3–6 bug** — it
is a Step 2 runtime characteristic inherited from the Netcracker
identity-provider fork — but it is easy to trip over during Phase 7
stability-check work. The recovery is always
`docker compose -f tests/parity/compose/docker-compose.yml down -v`
followed by a fresh `run-parity-suite.sh` cold run (53s end-to-end per
D-Y), which trivially works around the expiry.

Resolution: document the caveat in `tests/parity/README.md` under a
"Known Limitations" heading so Step 4 executor does not rediscover it
and does not misdiagnose a 403 as an Authz Agent regression.

- [x] **O4.1** — Added a "Known limitations" section to
      `tests/parity/README.md` with the license-expiry note.
      Suggested text:
      > **Keycloak license state expires after ~30 minutes of
      > uptime.** The Netcracker identity-provider fork used by the
      > parity stack runs a license-refresh SPI that stops producing
      > fresh state after a short window. Symptom: every OIDC token
      > request returns HTTP 403 `{"message": "License expired!"}`
      > and every suite test fails at `SetupSuite` during token
      > acquisition. Fix: `docker compose -f
      > tests/parity/compose/docker-compose.yml down -v && bash
      > tests/parity/scripts/run-parity-suite.sh` (a fresh cold run
      > takes ~53 s end-to-end and bypasses the expiry entirely).
      > Tracked as Step 2 Follow-up 1.8 / Gap 5.g; not a Step 3 bug.
- [x] **O4.2** — Kept as a documented Step 2 runtime caveat only.
      No new Step 3 follow-up was raised; the item remains out of scope
      for this handover and is sufficiently covered by the README note.
      Historical option kept for context:
      Optionally raise the finding to Step 2's Follow-up
      section as a **new Follow-up** if the maintainer of the
      identity-provider fork can be asked to lengthen the license
      window or make the SPI retry on expiry. Out of scope for Step 3
      — flag as an Open Question in this handover's Open Questions
      section if pursued.

### O5 — D-R wipe-and-reseed not wired into run-parity-suite.sh

D-R locked "wipe-and-reseed on every `run-parity-suite.sh` invocation
for deterministic developer iteration". The initial Phase 6 script only
seeded on first compose `up -d` via the `ac-seed` one-shot container,
so warm re-runs hit whatever policy state the **first** cold run left in
the legacy AC simplified-policy repository.

This is "pragmatically fine as long as nobody is editing fixtures
mid-session" — but it is a formal **D-R compliance gap**. Developer
iteration on fixture JSON does not take effect without a
`docker compose restart ac-seed` or an equivalent re-seed call, which
contradicts the D-R rationale ("developer who edits a fixture JSON
and re-runs the suite sees the new result without having to tear
the stack down with `docker compose down -v`").

Resolution options:

1. **(a) Wire re-seed into `run-parity-suite.sh`.** Between the "wait
   for healthy" step and the "run smoke.sh pre-flight" step, the
   script force-recreates the one-shot seed container via
   `docker compose -f "$COMPOSE_FILE" up -d --force-recreate --no-deps ac-seed`
   and waits for `parity-ac-seed` to exit 0 again. The Phase 3 seed
   loader is idempotent on re-PUT per legacy AC simplified-policy PUT
   semantics. Wall-clock budget impact: ~5–15s added per warm
   run, still comfortably under the D-Y 15-minute SLA.
2. **(b) Explicitly accept the deviation from D-R and document it.**
   The handover amends D-R to say "wipe-and-reseed runs on the first
   `run-parity-suite.sh` invocation of a fresh stack; subsequent
   warm runs reuse the seeded state unless the developer explicitly
   asks for a re-seed via
   `docker compose restart ac-seed`". Losing the D-R iteration
   guarantee but matching current reality.

- [x] **O5.1 — Decision:** chose **(a)**, wire re-seed into the script.
      The D-R rationale (developer iteration on fixtures) is real, and
      the added warm-run cost is small.
- [x] **O5.2** — Applied option (a): `run-parity-suite.sh` now force-recreates
      `ac-seed` after the health-wait loop, waits for `parity-ac-seed`
      to reach `exited:0`, and was re-verified post-commit on both cold
      (`53.24s`) and warm (`5.64s`) runs with `130/130` green.

### O6 — Move simplified-policy seeding **and smoke checks** out of compose into test SetupSuite (post-closure architectural follow-up, 2026-04-14 iteration 10, extended in iteration 11)

**Added after F1 + O1–O5 closure** per the parent plan owner ask in
iteration 10: "перенести загрузку политик из compose в setup тестов".
This item is **not** a validation finding against the landed Phase 3–6
work — the `130/130` green baseline and commit `98b5520` remain valid
— it is a **forward-looking architectural refactor** that unifies
fixture ownership under the Go test suite and removes the `ac-seed`
one-shot container's responsibility for seeding PARITY-domain
simplified policies. Step 4 will re-point the same suite at Authz
Agent and must exercise the same seed path, so landing O6 **before**
Step 4 drafting prevents Step 4 from inheriting the split-ownership
model and then refactoring it again.

**Iteration 11 extension (2026-04-14, same day).** The owner clarified:
`smoke.sh` itself moves into `SetupSuite` too, with a specific
execution ordering — "при запуске тестов сначала должен пройти смоук,
затем зачистка политик, затем заливка основных политик, а потом уже
тесты". This locks the O6 decision gate: the original
options (a) / (b.i) / (b.ii) / (c) below are **superseded** by
option **(b.ii) — full move + smoke-in-Go** with the iteration-11
execution order:

1. **SetupSuite phase 1 — smoke seed.** Wipe the `PARITY` domain
   (guarantee clean start), then PUT the 5 smoke fixtures
   (`ols-allow.json`, `ols-deny.json`, `rls-filter.json`,
   `general-pip.json`, `general-pip-pips.json`) from Go-owned
   testdata into the domain. This is a transient state — it exists
   only so the smoke phase has something to assert against.
2. **SetupSuite phase 2 — smoke run.** Execute the 12 smoke
   assertions (the current `smoke.sh` steps 1–12) as Go code against
   the transient smoke-seeded state. Each check fails the entire
   suite fast via `s.T().Fatalf` if it does not match the canonical
   shape. The 12 assertions are:
   1. `GET /api-version` returns integer byte shape per ADR-0049.
   2. `POST /token` (M2M client_credentials) returns a Bearer token.
   3. `POST /token` (end-user password grant) returns a Bearer token.
   4. `POST /pip-stub/reset` on `pip-mock` clears recorded calls.
   5. `POST /access/v1/check/resource` with the OLS allow fixture
      returns `true`.
   6. Same endpoint with the OLS deny fixture returns `false`.
   7. `POST /access/v1/check/filter` with the RLS filter fixture
      returns a non-trivial `calculationResult`.
   8. `POST /access/v2/check/resource?obligations=false` per **D3**.
   9. `POST /access/v1/check/resource` with the GENERAL-PIP fixture
      (pinned via `pip-mock`) returns `true` for an allowed id.
   10. `GET /pip-stub/calls` confirms the mock was actually reached.
   11. Same GENERAL-PIP fixture with a not-allowed id returns `false`.
   12. `POST /access/v1/check/resource` with
       `Authorization-Type: anonymous` returns a JSON Boolean.
3. **SetupSuite phase 3 — wipe.** `WipeDomain(PARITY)` empties
   both `domainPolicies/PARITY` and `domainPIPs/PARITY` so the
   transient smoke state does not leak into the test fixture pack.
4. **SetupSuite phase 4 — main seed.** `SeedDomain(PARITY, mainFS)`
   PUTs the full Step 3 fixture pack (the CLANG / AGG / SUB / ENT
   blocks plus the PSUITE base fixtures) from Go-owned testdata.
   PIPs before policies per the existing Step 3 seed-ordering
   constraint (legacy AC rejects policies whose `condition` references
   an undeclared PIP at PUT time).
5. **Test execution** — JUnit-equivalent per-row / per-sub-case
   test methods run against the freshly-seeded main fixture pack.

The test package (`paritysuite`) therefore owns the entire domain
state lifecycle. `tests/parity/scripts/smoke.sh` **is deleted**.
`tests/parity/scripts/run-parity-suite.sh` loses the smoke pre-flight
step and the `ac-seed` force-recreate step; it becomes
`docker compose up -d` → wait for healthy → `go test`.
`tests/parity/compose/docker-compose.yml` **drops the `ac-seed`
service entirely** because no compose-lifecycle component needs to
seed anything any more. `seed-access-control.sh` is deleted from the
compose seed tree. The 5 smoke fixtures **move** into
`tests/parity/suite/testdata/fixtures/smoke/` alongside the Step 3
main pack at `tests/parity/suite/testdata/fixtures/policies/`.

**D-H framing update.** The locked D-H text says "Step 2 `smoke.sh`
must stay 12/12 green after Phase 3 changes". Under iteration-11
O6, `smoke.sh` ceases to exist, so the literal D-H text cannot hold.
The **spirit** of D-H — "the 12 smoke assertions against the legacy
stack must keep passing" — is preserved by relocating the checks
into `SetupSuite` phase 2; if any of the 12 assertions fails, the
whole suite aborts at `SetupSuite` before any test method runs,
which is a strictly stronger regression-detection gate than the
bash pre-flight was. **D-H is amended under O6 landing:** the
compliance check moves from "`bash smoke.sh` prints
`Smoke run passed: 12/12 checks green.`" to "the Go SetupSuite
phase 2 prints `[paritysuite] smoke phase: 12/12 assertions green`
(or equivalent) and does not `Fatalf`". Executor is asked to emit
this line verbatim at the end of phase 2 so a grep in CI / debug
output catches smoke regressions without having to parse testify
output.

**Current state (post-F1 closure, commit `98b5520`):**

1. `tests/parity/compose/docker-compose.yml` ships a `parity-ac-seed`
   one-shot service that runs
   `seed-access-control.sh` (later removed),
   which `PUT`s every file under
   `tests/parity/compose/seed/policies/` (the bespoke smoke fixtures
   from Step 2 + the Step 3 `suite/` and `regular/` fixture packs)
   into legacy AC via `/access/v1/simplifiedPolicies/domainPolicies/PARITY`.
   Acquires its M2M token from the parity IdP via `client_credentials`
   against `parity-m2m`.
2. Step 2 `smoke.sh` (the 12/12 smoke script) runs against the seeded
   domain and depends on the 5 Step 2 smoke fixtures
   (`ols-allow.json`, `ols-deny.json`, `rls-filter.json`,
   `general-pip.json`, `general-pip-pips.json`) being present in the
   `PARITY` domain **before** `smoke.sh` executes.
3. Per O5 closure, `run-parity-suite.sh` force-recreates `ac-seed`
   after the health-wait loop for deterministic re-seed on every
   invocation.
4. The Go suite at `tests/parity/suite/` relies on the domain state
   `ac-seed` leaves behind; `SetupSuite` does **not** touch
   simplified-policy state.

**What the refactor should achieve:**

1. Simplified-policy seeding is driven from Go test setup, not from a
   compose-lifecycle container.
2. `SetupSuite` (or a subset-narrower hook invoked once per `go test`
   process) wipes the `PARITY` domain and re-seeds it from fixtures
   the Go module owns, against the same legacy AC endpoint the
   shell script currently hits.
3. Developer workflow for the debug run config
   (.run/authz-agent parity suite debug.run.xml)
   stops requiring a separate `docker compose restart ac-seed`
   between invocations — the Go process itself re-seeds.
4. Step 4's Authz Agent rerun inherits the new Go-driven seed path
   "for free" — no Authz-Agent-specific seed logic lives in compose
   or in a separate shell script.
5. Per **D-H**, Step 2 `smoke.sh` must still print
   `Smoke run passed: 12/12 checks green.` on a fresh cold bring-up.
   This is the hard constraint that bounds how aggressively `ac-seed`
   can be removed from compose.

**Design options** (pick one at **O6.1**; each has a different
trade-off on D-H and on fixture-file layout):

1. **(a) Split responsibilities — `ac-seed` keeps the 5 smoke
   fixtures, Go `SetupSuite` owns the Step 3 suite/regular packs.**
   - `seed-access-control.sh` is trimmed to only load
     `tests/parity/compose/seed/policies/{ols-allow,ols-deny,rls-filter,general-pip,general-pip-pips}.json`
     (the 5 files `smoke.sh` transitively depends on).
   - The `tests/parity/compose/seed/policies/suite/` and
     `tests/parity/compose/seed/policies/regular/` directories are
     **moved** into the Go module testdata tree, typical new
     location: `tests/parity/suite/testdata/fixtures/policies/suite/`
     and `tests/parity/suite/testdata/fixtures/policies/regular/`.
   - `run-parity-suite.sh` keeps the `ac-seed` force-recreate for
     the smoke fixtures, then runs `go test` which does its own
     wipe + re-seed of suite/regular contents via a new
     `suite/seed.go` helper.
   - D-H is preserved trivially: smoke fixtures stay where
     `smoke.sh` expects them, smoke keeps working with zero changes.
   - `SetupSuite` adds `~10–30s` to warm runs because every `go test`
     invocation now wipes + re-PUTs ~40 suite fixtures. Still comfortably
     inside D-Y `≤15 min` budget.
   - **Split ownership is the downside:** the 5 smoke fixtures and the
     40+ suite fixtures live in two different directories under two
     different ownership stories (compose for smoke, Go testdata
     for suite). Debuggable, but less unified than option (b).
2. **(b) Full move — Go `SetupSuite` owns every simplified-policy
   fixture, `ac-seed` is removed from compose.**
   - All fixture JSON files move into `tests/parity/suite/testdata/fixtures/policies/`.
   - `seed-access-control.sh` + the `ac-seed` compose service are
     deleted; `run-parity-suite.sh` stops force-recreating
     anything simplified-policy-related.
   - **D-H blocker:** `smoke.sh` runs **before** the Go suite
     starts (it is a bash+curl pre-flight, not a Go test), so it
     cannot depend on Go-process seed state. Two sub-options to
     preserve 12/12 smoke:
     - (b.i) **Rewrite `smoke.sh` to bootstrap its own seed.**
       `smoke.sh` gains a "seed the 5 smoke fixtures via curl"
       step at the top, using the same M2M token flow the Go
       suite uses. Adds shell complexity but keeps `smoke.sh` as a
       standalone bash pre-flight. Wall-clock impact on `smoke.sh`:
       `+2–5s` (5 PUTs).
     - (b.ii) **Extend the Go suite with a `SmokeCheck` subtest
       that replicates `smoke.sh`.** `smoke.sh` is deleted; the
       12 smoke assertions become a row 0 / row negative test in
       the Go catalogue, pinned to the legacy wire shapes. D-H is
       effectively re-framed as "the Go suite includes a smoke
       pre-flight that maps 1:1 to the old 12-check script".
       Most invasive option — touches Step 2 artefact surface.
   - **Full move is the upside:** one seed owner, one fixture
     directory, one language. Matches the owner's iteration-10 ask
     most literally.
3. **(c) Embed fixtures via `go:embed`, ship Go-only seed, keep
   `ac-seed` as a thin wrapper.**
   - All fixture JSON files are embedded into the Go binary via
     `//go:embed testdata/fixtures/policies/**/*.json`.
   - `SetupSuite` reads them from the embedded FS and `PUT`s the
     entire set over HTTP. Zero on-disk fixture dependency at
     runtime — the `go test` binary is fully self-contained.
   - `ac-seed` is simplified into a `go run` wrapper that invokes
     a new `cmd/ac-seed-go/main.go` binary which does the same
     thing `SetupSuite` does, called once from compose so
     `smoke.sh` still has a seeded domain to run against.
   - Pros: one fixture source-of-truth (the Go embed tree), no
     shell-script JSON handling, Step 4 inherits the exact same
     loader.
   - Cons: introduces a new Go binary (`cmd/ac-seed-go/`) that
     compose needs to build; adds one more image build step in
     `build-images.sh`. Most engineering work.

**Decision criteria the owner should weigh:**

- How much Step 2 artefact surface (`ac-seed`, `smoke.sh`,
  `seed-access-control.sh`) is allowed to change? Option (a) touches
  none, option (b.i) touches `smoke.sh`, option (b.ii) deletes
  `smoke.sh`, option (c) replaces `seed-access-control.sh` with a Go
  binary.
- How tightly do the 5 smoke fixtures need to stay under Step 2
  ownership vs being merged into the Step 3 fixture pack?
- Does Step 4 need a single seed path to clone, or can it live with a
  split (option a)?

**Executor recommendation:** start with **(a)**. It has the lowest
blast radius on D-H / Step 2 artefacts, does not require rewriting
`smoke.sh`, and still moves the Step 3 fixture pack out of compose —
which is the thing the owner actually asked for in one sentence.
Options (b) and (c) are larger refactors that can be tackled in a
dedicated follow-up if the owner wants full unification later.

**Close-out checklist** (sub-items flipped to `[x]` as executor works
through them. **O6.1 is locked to option (b.ii) by the iteration-11
owner extension** — the other options below remain in this handover
only as historical context for why (b.ii) was picked):

- [x] **O6.1 — Decision: option (b.ii) locked in iteration 11.**
      Full move + smoke-in-Go, with the iteration-11 SetupSuite
      execution order (smoke seed → smoke run → wipe → main seed →
      tests). `smoke.sh` is deleted; `ac-seed` compose service is
      deleted; `seed-access-control.sh` is deleted; fixture tree
      moves entirely into `tests/parity/suite/testdata/fixtures/`.
      Recommendation in earlier iterations was (a) for minimal
      blast radius, but iteration-11 owner extension explicitly
      picks (b.ii) for full unification.
- [x] **O6.2 — Go seed helper** (`tests/parity/suite/seed.go` new
      file): exposes `WipeDomain(ctx, cfg, domain string) error` and
      `SeedDomain(ctx, cfg, domain string, fixtureRoot fs.FS) error`.
      Implementation:
      - `WipeDomain` issues `PUT /access/v1/simplifiedPolicies/domainPolicies/{domain}`
        with an empty JSON array body **and** `PUT /access/v1/simplifiedPolicies/domainPIPs/{domain}`
        with an empty JSON array body (both are full-wipes per
        SimplifiedPolicyMappingService.java:80
        semantics). Called before every seed pass (smoke or main)
        so both passes have a deterministic empty start.
      - `SeedDomain` walks the given `fs.FS`, partitions files into
        simplified PIPs (`*-pips.json`), simplified policies, and the
        regular full-policy slice under `policies/regular/`. It PUTs the
        PIP payload first (per the Step 3 seed-ordering constraint
        "PIPs before policies so `condition` validation does not reject
        the batch"), then PUTs the simplified policies payload, then
        imports each regular full-policy file through
        `PUT /access/v1/policySets/externalId/{externalId}`. The main
        fixture pass preserves the legacy ordering `smoke baseline ->
        suite pack -> regular full-policy`.
      - Uses `TokenFactory.M2MToken()` for auth — no new token flow.
      - Returns structured errors that fail `SetupSuite` fast with a
        readable `s.T().Fatalf` message.
      - The seed helper is also the building block for the smoke
        phase — smoke calls `SeedDomain(ctx, cfg, "PARITY", smokeFS)`
        with an `fs.FS` rooted at the embedded smoke-fixture tree.
- [x] **O6.3 — Smoke phase package** (`tests/parity/suite/smoke.go`
      new file): exposes `RunSmokePhase(ctx, cfg, tokens *TokenFactory,
      pipMock *PipController) error`. Encodes the 12 smoke assertions
      listed in the iteration-11 extension above as a sequential
      Go function that:
      - Calls `HelperApiVersion(ctx, cfg)` and asserts the integer
        byte shape (step 1 — already implemented by Phase 2 helpers,
        reused verbatim).
      - Calls `tokens.M2MToken()` (step 2) and
        `tokens.EndUserToken(UserProfileReader)` (step 3); both must
        return non-empty strings without error.
      - Calls `pipMock.ResetCalls(ctx)` (step 4) via the existing
        Phase 2 helper.
      - Calls `HelperCheckResourceV1` with the OLS allow fixture
        body (step 5) and asserts `decision == true`.
      - Calls `HelperCheckResourceV1` with the OLS deny fixture body
        (step 6) and asserts `decision == false`.
      - Calls `HelperFilterV1` (step 7) and asserts
        `calculationResult != ""` and `rsqlFilterCondition != ""`.
      - Calls `HelperCheckResourceV2` (step 8) with `obligations=false`
        and asserts the response decodes.
      - Pins the GENERAL-PIP mock response (step 9), calls
        `HelperCheckResourceV1` with the GENERAL-PIP fixture body,
        asserts `decision == true`.
      - Calls `pipMock.GetCalls(ctx)` (step 10 — new method, wraps
        `GET /pip-stub/calls` per pipstub/main.go:50), asserts the
        `/api/v1/pip/allowed` path appears in the observed-calls list.
      - Re-pins the mock with an empty allow set (step 11), calls
        `HelperCheckResourceV1` with a different resource id,
        asserts `decision == false`.
      - Calls `HelperCheckResourceV1` with the anonymous token
        bundle (step 12) and asserts the response decodes as a JSON
        Boolean (either `true` or `false`; the canonical shape is
        the JSON boolean literal, not an error).
      - On success, emits a log line matching
        `[paritysuite] smoke phase: 12/12 assertions green`
        (literal, for grep-ability in CI / debug output).
      - On any assertion failure, returns a wrapped error naming
        the failing step number; `SetupSuite` converts that into
        `s.T().Fatalf` so the whole suite aborts before any test
        method runs.
- [x] **O6.4 — Fixture relocation.** Move the entire seed tree out
      of compose into Go-owned testdata:
      - `tests/parity/compose/seed/policies/ols-allow.json`,
        `ols-deny.json`, `rls-filter.json`, `general-pip.json`,
        `general-pip-pips.json` →
        `tests/parity/suite/testdata/fixtures/smoke/`.
      - `tests/parity/compose/seed/policies/suite/*` →
        `tests/parity/suite/testdata/fixtures/policies/suite/`.
      - `tests/parity/compose/seed/policies/regular/*` →
        `tests/parity/suite/testdata/fixtures/policies/regular/`.
      - All moves are `git mv` so history is preserved.
      - **Delete** `tests/parity/compose/seed/policies/` (now empty),
        `tests/parity/compose/seed/scripts/seed-access-control.sh`,
        and `tests/parity/compose/seed/scripts/` (if no other scripts
        remain there).
      - Fixtures are loaded via `//go:embed testdata/fixtures/smoke/*.json`
        for the smoke pack and `//go:embed testdata/fixtures/policies/suite/*.json
        testdata/fixtures/policies/regular/*.json` for the main
        pack. The seed helper takes `fs.FS` so either option (embed or
        plain filesystem) works; embed is preferred because it makes
        the `go test` binary fully self-contained.
- [x] **O6.5 — `SetupSuite` wiring** in `suite_test.go`. Replace
      the current `SetupSuite` body with the iteration-11 execution
      order:
      ```go
      func (s *ParitySuite) SetupSuite() {
          s.cfg = LoadConfig()
          if err := EnsureRecordModeSafe(s.cfg); err != nil {
              s.T().Fatalf("%v", err)
          }
          s.tokens = NewTokenFactory(s.cfg)
          s.comparator = NewGoldenComparator(s.cfg)
          s.pipMock = NewPipController(s.cfg.PipMockControlURL)
          s.eaMock = NewPipController(s.cfg.EAMockControlURL)
          ctx := context.Background()
          // Phase 1: smoke seed — clean start, then pin the 5 smoke fixtures.
          if err := WipeDomain(ctx, s.cfg, s.cfg.DomainName); err != nil {
              s.T().Fatalf("wipe before smoke seed: %v", err)
          }
          if err := SeedDomain(ctx, s.cfg, s.cfg.DomainName, smokeFixtureFS); err != nil {
              s.T().Fatalf("seed smoke fixtures: %v", err)
          }
          // Phase 2: smoke run — 12 assertions, abort whole suite on any failure.
          if err := RunSmokePhase(ctx, s.cfg, s.tokens, s.pipMock); err != nil {
              s.T().Fatalf("smoke phase: %v", err)
          }
          // Phase 3: wipe — drop smoke state so main fixtures see a clean domain.
          if err := WipeDomain(ctx, s.cfg, s.cfg.DomainName); err != nil {
              s.T().Fatalf("wipe after smoke: %v", err)
          }
          // Phase 4: main seed — full Step 3 fixture pack.
          if err := SeedDomain(ctx, s.cfg, s.cfg.DomainName, mainFixtureFS); err != nil {
              s.T().Fatalf("seed main fixtures: %v", err)
          }
          // Test methods run after SetupSuite returns.
      }
      ```
      Record mode (`PARITY_GOLDEN_RECORD=1`) does NOT skip any phase
      — record mode needs the same fixtures the non-record run uses.
      M2M token is cached per the existing `TokenFactory` semantics
      so the seed calls + smoke token acquisitions share one token.
- [x] **O6.6 — Compose simplification** (`tests/parity/compose/docker-compose.yml`):
      - **Delete** the `ac-seed` service block entirely (lines
        defining `parity-ac-seed` + its volumes, dependencies, env).
      - Leave every other service (`postgres`, `idp`, `access-control`,
        `pip-mock`, `entitlements-mock`, `ac-token-fetcher`)
        untouched — they are still needed for the stack itself.
      - Verify `docker compose config` still parses after the
        deletion.
- [x] **O6.7 — `run-parity-suite.sh` simplification**:
      - **Delete** the `docker compose up -d --force-recreate
        --no-deps ac-seed` step added by O5. Nothing to re-run.
      - **Delete** the "pre-flight `smoke.sh`" step. Go owns smoke.
      - **Delete** the wait-for-`parity-ac-seed`-`exited:0` loop.
      - Keep: `docker compose up -d`, wait for every remaining
        service to reach healthy, `cd tests/parity/suite && go test
        -tags integration -run ^TestParitySuite$ -count=1 -v ./...`,
        leaf-counter, final line printer.
      - Final script is materially shorter — most of the Phase 6
        plumbing becomes one `go test` invocation + the health-wait
        prelude.
- [x] **O6.8 — `smoke.sh` deletion.** `tests/parity/scripts/smoke.sh`
      is deleted in the same commit as the compose edit. Any
      documentation mention of `smoke.sh` (in this handover, in
      `tests/parity/README.md`, in Step 2 handover references) is
      either updated to point at the Go smoke phase or removed.
      **Step 2 handover** references to `smoke.sh` stay as
      historical context — Step 2's landing happened before
      iteration 11 and re-writing Step 2 history is out of scope;
      adding a one-line forward pointer is enough.
- [x] **O6.9 — Suite revalidation.** Re-run
      `bash tests/parity/scripts/run-parity-suite.sh` cold and warm
      post-O6 changes. Both must still print `Parity suite passed:
      130/130 cases green.`; `git status --short tests/parity/suite/testdata/`
      must stay empty; `*.observed.json` sidecar count must be 0;
      the Go smoke phase must print
      `[paritysuite] smoke phase: 12/12 assertions green` as part
      of the `go test -v` output. Cold and warm wall-clock recorded
      in the Execution Report. Verified after O6 landing: cold
      `45.43s`, warm `1.57s`, `0` `*.observed.json`, stack healthy.
- [x] **O6.10 — Debug .run config compatibility.** Verify the
      .run/authz-agent parity suite debug.run.xml
      still works: start the stack manually via `docker compose up -d`,
      launch the debug config from GoLand, confirm `SetupSuite`
      runs all four phases (smoke seed → smoke run → wipe → main
      seed) and all 130 leaves run green end-to-end. This is the
      main developer workflow this refactor unblocks — the debug
      run used to require a manual `docker compose restart ac-seed`
      between invocations to pick up fixture edits; post-O6 this is
      no longer needed, and a debugger-breakpointed session can
      step through the smoke phase before the main tests start.
      Verified in this landing via the CLI-equivalent command from the
      `.run` file (`go test -v -count=1 -timeout 0 -tags integration
      -run ^TestParitySuite$` with the exact `PARITY_*` env block),
      which reproduced the smoke marker and passed all 130 leaves.
- [x] **O6.11 — Documentation**:
      - `tests/parity/README.md` "Seeding" section is replaced by
        a new "Test lifecycle" section describing the four
        `SetupSuite` phases and the testdata fixture layout.
      - The existing "Known limitations" section (O4) stays; the
        Keycloak license caveat still applies because it lives at
        the stack level, not the seed level.
      - This handover's Phase 3 bullet list, the **D-H** decision
        text (see amendment above), and the **D-R** decision text
        are updated. **D-H** amendment locks the Go-phase
        compliance check in place of the bash-script one. **D-R**'s
        "How to apply" paragraph moves from "`docker compose restart
        ac-seed`" to "SetupSuite phases 1 + 3 + 4 together own the
        wipe-and-reseed guarantee — every `go test` invocation
        wipes + re-seeds from a fresh start".
      - Parent plan Status and Handovers row text are updated to
        reflect the post-O6 landing.
- [x] **O6.12 — Landing commit.** A single git commit that carries
      the seed helper (O6.2), the smoke phase (O6.3), the fixture
      relocation (O6.4), the SetupSuite wiring (O6.5), the compose
      edit (O6.6), the `run-parity-suite.sh` edit (O6.7), the
      `smoke.sh` deletion (O6.8), the validation-report update, and
      the doc updates (O6.11). Commit message references this O6
      section. Post-commit: a second cold + warm run per O6.9 must
      stay green before Phase 7 is flipped `[x]`.

**Does O6 reopen F1 / O1–O5?** No. The landed baseline from commit
`98b5520` (130/130 green, committed goldens, stability verified) is
untouched by this refactor — O6 only changes **how** the fixtures
reach legacy AC, not **which** fixtures or **what** the golden set
expects. Post-O6 revalidation (O6.9) must reproduce the exact same
`130/130` count and zero diff against the committed golden tree. If
any golden diverges, O6 broke fixture loading and must be rolled
back; it does not invalidate the baseline.

**Does O6 block Step 4?** **Not any more.** O6 is now closed, so Step 4 can
inherit the unified Go-owned lifecycle instead of a compose-coupled seed path.
Parent plan Status reflects this: Step 4 drafting is unblocked again.

### Follow-up landing order

Recommended execution order:

1. **F1** first (blocker for Step 4). Commit goldens + test files +
   seed fixtures + tracked-modified edits in a single landing commit
   (or two: one for suite code + goldens, one for seed + compose).
2. **O5** second. Either wire re-seed into `run-parity-suite.sh`
   (option a) or amend D-R (option b). If option a, re-run cold/warm
   post-commit to confirm `130/130` still holds.
3. **O4** third. Add the README "Known limitations" section.
4. **O1 + O2** fourth. Owner picks (a) for both; handover spec text
   is updated to match reality.
5. **O3** fifth. Proofread + trivial updates.
6. **O6** sixth (added post-closure in iteration 10, extended in
   iteration 11). Architectural refactor: move both the
   simplified-policy seed path and the smoke pre-flight from
   compose into Go `SetupSuite` under the locked four-phase order
   (smoke seed → smoke run → wipe → main seed → tests). Must land
   before Step 4 drafting so Step 4 inherits the unified loader
   and the Go-based smoke check. F1 + O1–O5 landed already
   (commit `98b5520` + `1f06e0c`); O6 is the outstanding item
   reopening Phase 7 per D-W point 6. **D-H is amended** by this
   refactor — see O6's D-H framing update above.

After all seven items are checked, Step 3 is formally closed per
D-W, and Step 4 handover drafting begins per D-Q.

## Next Steps

*TBD.*
