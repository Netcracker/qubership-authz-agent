# Profiler Assets

This directory profiles the token checks of the embedded Rego policies in `policies/` with `opa eval --profile` and
`opa bench`. The two scenarios below are the only ones: the decision of a check request comes from the Rego module the
agent generates for each tenant, which no scenario here profiles.

## Scenario directories

- `identity-verify-token`: cached `data.authn.verifiedTokens` fast path
- `identity-validate-jwt`: full JWT/JWKS validation path with fixed test-only user/service tokens

Each scenario directory contains:

- `data.json`: the `data.authn` document the query reads
- `input.json`: the request input of the scenario
- `profile.sh`: a minimal wrapper around `opa eval --profile`
- `bench.sh`: a wrapper around `opa bench` with `5` runs
- `profile-trace.sh`: a wrapper around `opa eval --explain=full`

The `identity-verify-token` directory profiles the cached path:

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

## Usage

```bash
tests/svt/profiler/<scenario>/bench.sh
tests/svt/profiler/<scenario>/profile.sh
tests/svt/profiler/<scenario>/profile-trace.sh
```

The scripts run `opa` from `PATH`, as `test/scripts/test-opa.sh` does; `mise install` puts the version
`mise.toml` pins there. Override with `OPA_BIN=/path/to/opa` if needed.
