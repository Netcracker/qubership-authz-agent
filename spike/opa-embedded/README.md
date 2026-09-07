# opa-embedded spike

A spike, not a product component: OPA as a Go library behind the Fiber server of the Qubership core libraries. The
binary drops into the chart's OPA container unchanged and presents the slice of OPA's REST API the Pod uses, so the
runtime suite and the parity replay run against embedded OPA without any other change.

| OPA feature the Pod relies on | Spike |
| --- | --- |
| `opa run --server --addr ... --ignore=..* --authorization=basic --authentication=token --config-file ... <dirs>` | The same arguments; unknown flags are accepted and ignored |
| Policies and data loaded from the mounted directories | OPA's own `loader` package, then `ast.Compiler` and an in-memory store |
| `POST /v1/data/<path>` for Envoy and the suites | Prepared `rego` queries per path, `{"decision_id", "result"}` answers |
| `PUT` / `PATCH` / `GET /v1/data/<path>` for pap-client | Store transactions; JSON Patch on a missing document answers 404 |
| `data.system.authz.allow` guarding every request | Evaluated for each data API request with the bearer token as identity |
| Decision logs to the collector | Batched gzip uploads to the configured service with `nd_builtin_cache` and the configured request headers |
| `GET /health` | 200 `{}` |

Run it on the kind stand:

```bash
docker build -f spike/opa-embedded/Dockerfile -t local/opa-embedded:ci . && kind load docker-image local/opa-embedded:ci --name authz-e2e
helm --kube-context kind-authz-e2e upgrade authz-agent charts/authz-agent -n authz-e2e -f test/k8s/values.yaml --set OPA_IMAGE=local/opa-embedded:ci --wait
make e2e-suite
```

## Findings, 2026-09-07

The spike answered the four questions it was built for.

| Question | Answer |
| --- | --- |
| Does the Rego compile and behave on the OPA library (v1.20.2)? | Yes. The 21 policy modules compile as they are; the 352 Rego unit tests pass on the 1.20.2 CLI. |
| Do the builtins behave in-process as in the server? | Yes. `io.jwt.decode_verify` against the JWKS in the store, `http.send` to the PIP and entitlements stubs, and `nd_builtin_cache` in the decision logs all work through the `rego` package. |
| Byte-level parity? | Yes. The runtime suite passes all 20 groups (including both catalog coverage checks) and the parity replay passes on kind with the OPA container swapped for this binary and nothing else changed. |
| Cost | On par with the OPA image: the runtime suite takes 86 s against 88 s, the 3000-id bulk step 9.4 s against 10.2 s. Two PIP-calling steps are slower (`pip_general.active_pip_called` 395 ms against 11 ms); the `rego` package runs without OPA's inter-query builtin cache, which the real service should configure. |

Two things cost a day and matter for the real service:

- **Fiber hands out strings that alias fasthttp's request buffer.** A path segment taken from `c.Params` and stored as a key
  in the OPA store was rewritten by the next request, so `data.policies` "disappeared" at random while `GET /v1/data`
  still showed it. Anything that outlives the handler must be copied: the spike sets `Immutable: true` and clones the
  segments. With OPA embedded, the real service should feed the store from Go values, never from request strings.
- **Decision logs must be drained on shutdown with their own context.** The event of the last decision before
  `SIGTERM` was lost until the uploader flushed with a fresh deadline and `main` waited for it; the suite's coverage
  check caught it.

Not a finding: decoding the data API bodies with OPA's `util.UnmarshalJSON` instead of `encoding/json` looked like a
fix for a while, but both decoders produce identical values for these documents; the apparent effect was the aliasing
above.
