# Test Baseline

Reference results for every suite in this repository, measured 2026-08-19 from a
clean local clone. All base images come from public registries (Docker Hub,
quay.io); no external infrastructure is required beyond Docker.

## Suite Results

| Suite | Command | Exit code | Result | Notes |
| --- | --- | --- | --- | --- |
| Root module unit tests | `go test -count=1 ./...` (repo root) | 0 | 249 tests, 6 packages PASS | — |
| Integration-tagged compile check | `go vet -tags integration ./...` (root + each test module) | 0 | clean | The tag makes the compiler check the Docker-dependent suites |
| OPA policy tests | `opa test policies/` | 0 | 352/352 PASS | — |
| Parity module unit tests | `cd test/parity/suite && go test -count=1 ./...` | 0 | PASS | Unit-level only (no Docker) |
| Testify module unit tests | `cd test/integration/testify && go test -count=1 ./...` | 0 | PASS | Spec conformance/lint/drift; the in-cluster suite needs the tag |
| Pipstub module unit tests | `cd test/integration/pipstub && go test -count=1 ./...` | 0 | PASS | — |
| Chart render | `helm template charts/authz-agent` | 0 | one Deployment, one container | `test/scripts/test-chart-render.sh` asserts what the render has to carry |
| Runtime suite on kind | `make e2e` | 0 | 19 groups PASS | Includes the `m2m_keycloak.*` steps and both catalog coverage checks |
| Parity replay on kind | `make parity` | 0 | 135/135 PASS | Replays frozen goldens — see `test/parity/README.md` for what the goldens pin |

## Environment Notes

- The kind suites need no host ports.
- Keycloak (`quay.io/keycloak/keycloak:26.3.5`, UBI9-minimal) has no `curl`/`wget`.
  `KC_HTTP_RELATIVE_PATH=/auth` prefixes the management paths too. Cold start with
  augmentation can take ~60 s on first pull.
- Golden collection is not possible from this repository: the goldens under
  `test/parity/suite/testdata/golden/` are a frozen capture — see
  `test/parity/README.md`.
