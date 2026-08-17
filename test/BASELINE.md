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
| Testify module unit tests | `cd test/integration/testify && go test -count=1 ./...` | 0 | PASS | Spec conformance/lint/drift; Docker suites need the tag |
| Pipstub module unit tests | `cd test/integration/pipstub && go test -count=1 ./...` | 0 | PASS | — |
| Chart render | `make copy-policies && helm template charts/authz-agent` | 0 | policy ConfigMap populated (21 Rego files) | `charts/authz-agent/files/opa/policies/` is generated, never edited |
| Integration compose stack + testify suite | `bash test/scripts/test-envoy-runtime.sh` | 0 | 164 PASS, 0 FAIL, 2 SKIP | 2 SKIPs are `m2m_keycloak.*` steps — expected without `RUN_M2M_KEYCLOAK_PROFILE=true` |
| Parity replay | `PARITY_PROFILE=authz-agent bash test/parity/scripts/run-parity-suite.sh` | 0 | 135/135 PASS | Replays frozen goldens — see `test/parity/README.md` for what the goldens pin |
| SVT load harness smoke | `bash test/svt/scripts/up` | 0 | 1 request served, 200 OK | Starts the stack, seeds policies, fires one `POST /access/v1/check/resource`, tears down |

## Environment Notes

- The integration and SVT stacks publish ports 18080/18085/18090/15556; they must
  be free when the suites run.
- Keycloak (`quay.io/keycloak/keycloak:26.3.5`, UBI9-minimal) has no `curl`/`wget`;
  the compose healthchecks use bash `/dev/tcp` against the management port 9000.
  `KC_HTTP_RELATIVE_PATH=/auth` prefixes the management paths too. Cold start with
  augmentation can take ~60 s on first pull.
- The Envoy image ships `wget`, not `curl`; its healthchecks use
  `wget -q -O /dev/null http://localhost:9901/ready`.
- `TestOPARestart` is order-independent: restarting the OPA container replaces its
  network namespace, so the test also restarts `pap-client` (which runs with
  `network_mode: "service:opa"`) once OPA is healthy again, then polls the
  pap-client `/health` endpoint until a pull cycle completes before asserting
  decisions. Later tests therefore never observe stale OPA state.
- Golden collection is not possible from this repository: the goldens under
  `test/parity/suite/testdata/golden/` are a frozen capture — see
  `test/parity/README.md`.
