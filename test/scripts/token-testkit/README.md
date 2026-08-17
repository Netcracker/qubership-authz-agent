# Token Testkit Scripts

Scripts in this directory generate key/JWKS material and issue signed JWT tokens for Rego/policy tests and fixture maintenance.

## Scripts

1. `generate-rsa-jwks.sh`
   - Creates RSA keypair, JWKS, trusted providers config, and manifest.
2. `mint-jwt.sh`
   - Issues one RS256 JWT with configurable claims.
3. `generate-token-fixture-set.sh`
   - Builds a reusable fixture set of valid/invalid test tokens.
4. `refresh-rego-fixtures.sh`
   - Regenerates the committed Rego fixture files used under `policies/`.

## Typical flow

```bash
test/scripts/token-testkit/generate-rsa-jwks.sh
test/scripts/token-testkit/generate-token-fixture-set.sh
test/scripts/token-testkit/refresh-rego-fixtures.sh
```

Generated artifacts are written to `/tmp/authz-token-testkit` by default.
These scripts are not used by `test/scripts/test-envoy-runtime.sh`, which requests runtime tokens from Keycloak.
