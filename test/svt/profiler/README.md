# Profiler Assets

This directory contains static OPA profiler inputs for the direct-to-OPA SVT scenarios.

## Consolidated benchmark report

`tests/svt/scripts/bench-report` runs `opa bench` for every profiler scenario variant, selects
the best run, and emits a consolidated Markdown report.

```bash
# Full run (10 invocations per scenario, ~15 min)
tests/svt/scripts/bench-report

# Quick smoke test (1 invocation per scenario)
tests/svt/scripts/bench-report --runs 1
```

Reports are written to `tests/svt/profiler/artifacts/bench-report-<timestamp>.md` (gitignored).
If all p95 values are equal to or better than the current baseline, the report is automatically
promoted to `docs/reports/bench-report-latest.md` (committed).

## Scenario directories

### OLS scenarios

- `ols-single` — single-resource OLS authorization with 1 admin role
- `ols-single-10roles` — 10 subject roles
- `ols-single-20roles` — 20 subject roles
- `ols-single-30roles` — 30 subject roles
- `ols-single-50roles` — 50 subject roles
- `ols-single-100roles` — 100 subject roles
- `ols-bulk-50` — bulk OLS with 50 resources
- `ols-bulk-100` — bulk OLS with 100 resources
- `ols-bulk-1000` — bulk OLS with 1000 resources

### RLS condition-expression scenarios

- `rls-condition` — 1 conditionAst expression (alias: `rls-condition-1-expression`)
- `rls-condition-2-expression` — 2 conditionAst expressions per rule
- `rls-condition-3-expression` — 3 conditionAst expressions per rule
- `rls-condition-5-expression` — 5 conditionAst expressions per rule

### RLS predicate scenarios

- `rls-predicate` — single predicate with 1 token PIP
- `rls-predicate-summary-2-predicates` — 2 independent predicate objects
- `rls-predicate-summary-3-predicates` — 3 independent predicate objects
- `rls-predicate-summary-4-predicates` — 4 independent predicate objects
- `rls-predicate-summary-5-predicates` — 5 independent predicate objects
- `rls-predicate-summary-10-predicates` — 10 independent predicate objects

### RLS predicate-pips scenarios

- `rls-predicate-pips` — 1 token PIP + 1 header PIP (original mixed baseline, excluded from report)
- `rls-predicate-pips-1-token-pip` — 1 token PIP
- `rls-predicate-pips-2-token-pip` — 2 token PIPs
- `rls-predicate-pips-3-token-pip` — 3 token PIPs
- `rls-predicate-pips-1-header-pip` — 1 header PIP
- `rls-predicate-pips-2-header-pip` — 2 header PIPs
- `rls-predicate-pips-3-header-pip` — 3 header PIPs
- `rls-predicate-summary-10-predicates-3-token-pip` — combined stress: 10 predicates × 3 token PIPs

### Wildcard-access scenarios (ADR-0040)

- `wildcard-all-single` — single resource with `globalAccessRoles.byRole[role].all = true`
  (request-level short-circuit, skips OLS/RLS entirely)
- `wildcard-mixed-bulk` — 50 resources: 25 matched by `resourceTypes` wildcard (short-circuit),
  25 through normal exact OLS (same background policy data as `ols-bulk-50`)

### Identity scenarios

- `identity-verify-token` — cached `data.authn.verifiedTokens` fast path
- `identity-validate-jwt` — full JWT/JWKS validation path with fixed test-only user/service tokens

Each scenario directory contains:

- `data.json`: runtime-normalized `data.authn`, `data.policies`, and `data.pips`
- `input.json`: one representative request input for the scenario
- `profile.sh`: a minimal wrapper around `opa eval --profile`
- `bench.sh`: a wrapper around `opa bench` with `5` runs
- `profile-trace.sh`: a wrapper around `opa eval --explain=full`

Authorize-result scenarios (`ols-*`, `rls-*`, and `wildcard-*`) also provide an additive
real-token variant:

- `data-real-token.json`: trusted-provider + JWKS overlay for full JWT validation
  using canonical authn runtime data (`trustedProviders.byId` + `jwksByKid`, authz-agent-ADR-0075)
- `input-real-token.json`: same scenario input with a fixed signed bearer token instead of the
  cached synthetic token
- `profile-real-token.sh`: `opa eval --profile` wrapper for the merged cached-scenario data plus
  the real-token authn overlay
- `bench-real-token.sh`: `opa bench` wrapper for the same merged real-token authorize path

The `identity-verify-token` directory is intentionally narrower:

- `data.json`: focused authn cache fixture for `data.identity.verify_token("svt-profiler-token")`
- `input.json`: empty placeholder for wrapper consistency
- `profile.sh`: line profiler for the direct `identity.verify_token` query
- `bench.sh`: bench wrapper for the direct `identity.verify_token` query with `5` runs
- `profile-trace.sh`: full explain trace for the same direct query

The assets use a synthetic cached bearer token in `data.authn.verifiedTokens`, so profiling does
not depend on Keycloak, JWKS, or token expiration.

The `identity-validate-jwt` directory complements that cached-path microprofile with a cold-path
JWT validation fixture:

- `data.json`: focused indexed trusted-provider + JWKS/JWKS-JSON fixture for signature validation
- `input.json`: two fixed test-only tokens (`user` and `service`) that expire on
  `2100-01-01T00:00:00Z`
- `profile.sh`: line profiler for `data.identity.verify_token(...)` with real JWT decode/verify
- `bench.sh`: bench wrapper for the same cold-path validation query with `5` runs
- `profile-trace.sh`: full explain trace for the same cold-path validation query

Use `TOKEN_KIND=user` or `TOKEN_KIND=service` to choose which token the wrappers validate.

The authorize real-token variants use signed JWTs generated by `keys/sign-jwt.py` with the RSA
key pair in `keys/`. Each scenario variant has a JWT with the appropriate role set and extra claims.

## Keys

- `keys/profiler-rsa-private.pem` — RSA 2048-bit private key (test-only)
- `keys/profiler-rsa-public.pem` — corresponding public key
- `keys/sign-jwt.py` — JWT signing helper (Python 3 stdlib + openssl)

```bash
# Sign a JWT with custom roles and extra claims
python3 tests/svt/profiler/keys/sign-jwt.py --roles "ROLE_SVT_01,ROLE_SVT_02"
python3 tests/svt/profiler/keys/sign-jwt.py --roles "ROLE_SVT_ADMIN" --extra-claims '{"department":"dept-01"}'
```

## Usage

```bash
# Consolidated benchmark report (recommended)
tests/svt/scripts/bench-report --runs 1   # smoke test
tests/svt/scripts/bench-report             # full 10-run report

# Individual scenario bench/profile
tests/svt/profiler/<scenario>/bench-real-token.sh
tests/svt/profiler/<scenario>/profile-real-token.sh
tests/svt/profiler/<scenario>/profile-trace.sh
```

By default the scripts use the repository-local binary at `test/tools/opa/opa`, matching
`test/scripts/test-opa.sh`. If that binary is missing they fall back to `opa` from `PATH`.
Override with `OPA_BIN=/path/to/opa` if needed.
