# Verify tokens before policy evaluation against the keys of trusted issuers

## Status

Proposed

<!-- markdownlint-disable-next-line MD001 -->
#### Owner

kichasov

#### Participants and approvers

- The project architect (`mr-joom`) approves this record, and with it the answers it takes from the owner of the policy
  decision code on realms, key selection, reloads, and checks.
- The owner of the policy decision code (`vlsi`) returned the questionnaire of 2026-11-03.
- The Netcracker/qubership-authz-agent maintainers (kichasov).

#### Related ADRs

- [authz-agent-ADR-0080: Replace Envoy, the Lua filters, and the OPA container with one Go service that embeds OPA](20260907-authz-agent-adr-0080-single-go-service-with-embedded-opa.md):
  this record supersedes these statements. Under "Handlers instead of Lua": the check routes refuse a missing or invalid
  token in `Authorization` before the policies run (ADR-0092 R1, R2), the policies no longer validate the tokens (R58),
  and the handlers no longer build the same input as before, because the compact tokens leave it (R76). Under
  "In-process supporting logic": the JWKS bootstrap no longer writes keys into the store (R67), and the reload of the
  trusted providers file goes away (R12).
- [authz-agent-ADR-0092: Accept any verified token in Authorization and limit a caller that is not M2M to its tenant](20261029-authz-agent-adr-0092-tokens-in-authorization.md):
  ADR-0092 R6 to R8 and R21, the M2M test whose result the verification returns.
- [authz-agent-ADR-0093: Take the tenant of a decision from the verified user token, then from the request](20261029-authz-agent-adr-0093-tenant-of-a-decision.md):
  ADR-0093 R10 to R14, the default tenant, and ADR-0093 R17, the policy snapshots that readiness waits for.
- [authz-agent-ADR-0094: Accept Kubernetes service account tokens from the namespaces of the installation](20261029-authz-agent-adr-0094-kubernetes-service-account-tokens.md):
  ADR-0094 R1 to R13 and R26 to R29, the marked provider and its tokens, and ADR-0094 R14 to R25, the extra checks of a
  Kubernetes token.
- [authz-agent-ADR-0095: Refuse a check request before policy evaluation](20261029-authz-agent-adr-0095-refuse-before-policy-evaluation.md):
    ADR-0095 R16, the index of the reason codes.
- [authz-agent-ADR-0096: Choose the token the agent sends with a setting of its own](20261105-authz-agent-adr-0096-token-the-agent-sends.md):
  the agent's token, which liveness does not depend on.

## Context

A check route of the agent receives two tokens: the caller's token in `Authorization` and, optionally, the user's token
in `Incoming-Token`. Today Go fetches the keys of the trusted providers into the store as `data.authn`, and
`policies/identity.rego` parses and verifies both tokens on every evaluation. The token rules are split between the Go
code that loads keys and the Rego that checks claims, and a request with a bad token is evaluated before it is refused.

Every tenant has its own realm in one Keycloak, and the name of the realm is the identifier of the tenant. A token of a
realm names that realm in `iss`: `<address>/auth/realms/<realm>`. The agent runs in Kubernetes and on plain Linux, where
no tenant-manager may exist.

This record and ADR-0092 to ADR-0096 replace the numbers ADR-0084 to ADR-0086, which are retired. ADR-0084 became
ADR-0091, ADR-0092, and ADR-0095, ADR-0085 became ADR-0093 and the realms of ADR-0091, and ADR-0086 became ADR-0094 and
ADR-0096.

## Decision

We will verify every token in Go against the keys of the trusted issuers before the decision is evaluated.

### Terms

- **Trusted providers file**: the file that R73 describes, which the agent reads at start.
- **Provider**: an entry of `providers` in the trusted providers file.
- **Marked provider**: a provider with `kubernetes: true`. ADR-0094 decides what it does.
- **Realm**: a realm of the Keycloak that `keycloak.url` of the trusted providers file names.
- **Source**: a realm or a provider, as a place that keys are read from.
- **Required source**: a provider, or a realm in `keycloak.requiredRealms`.
- **Load**: one attempt to read the keys of one source, discovery included. A reload is any load of a source after its
  first one.
- **On-demand load**: a load that a token starts. The hourly reload is not one.
- **Realm token**: a token whose `iss` contains `/auth/realms/` and matches no provider.
- **File token**: a token of a provider that is not marked.
- **Kubernetes token**: a token that a key of a marked provider verifies.
- **Issuer**: the value in the `iss` of a token. A provider holds it in `issuer`.
- **Stops the start**: the agent exits with an error before it serves a request. A package below `startup` reports this
  by returning an error from its constructor or parser.

These records use no wider word for a realm token and a file token together. The word Keycloak names the server.

### Rules

#### Trusted issuers

- **R73** (`keys`). The trusted providers file holds `keycloak`, with `url`, `requiredRealms`, and `caFile`, and
  `providers`, the list of providers. It holds at least one of the two, and anything else stops the start.
- **R1** (`keys`). `keycloak.url` names one Keycloak, and every realm of that Keycloak is trusted.
- **R2** (`keys`). `keycloak.caFile` holds the CA of the requests to that Keycloak.
- **R72** (`chart`). The chart sets `keycloak.url` from `IDENTITY_PROVIDER_URL`, and, with `INTERNAL_TLS_ENABLED`,
  `keycloak.caFile` from `CERTIFICATE_FILE_PATH`.
- **R78** (`keys`). The agent does not read `IDENTITY_PROVIDER_URL`.
- **R3** (`keys`). The realm of a realm token is the part of `iss` after the last slash, percent-decoded. The host of
  `iss` is not compared.
- **R4** (`keys`). The keys of a realm are read through OIDC discovery at `<keycloak.url>/auth/realms/<realm>`,
  never from the host in `iss`.
- **R5** (`keys`). A realm name of `.` or `..`, with a slash, or longer than 255 bytes is refused with
  `TOKEN_ISSUER_UNKNOWN`. Every other character is escaped in the address.
- **R6** (`keys`). A provider has the fields `id`, `issuer`, `jwksUri`, `audiences`, `allowMissingAud`, `caFile`,
  `tokenFile`, and `kubernetes`.
- **R7** (`keys`). The `iss` of a token matches the `issuer` of a provider byte for byte. A match takes precedence over
  the realm rule, so a token that also contains `/auth/realms/` in `iss` is then not a realm token.
- **R8** (`keys`). A marked provider does not set `issuer`, because ADR-0094 R4 gives it one. A marked provider that
  sets `issuer` stops the start.
- **R9** (`keys`). A provider with `jwksUri` reads its keys at that address without discovery.
- **R10** (`keys`). The token at a provider's `tokenFile` is sent only with the requests for that provider's keys.
  ADR-0094 R12 limits where the token for the API server goes.
- **R11** (`verify`). A token whose `iss` is missing, or matches no provider and does not contain `/auth/realms/`, is
  refused with `TOKEN_ISSUER_UNKNOWN`. So is a realm token when the file holds no `keycloak`.
- **R12** (`startup`). The agent reads the trusted providers file at start and does not read it again.
- **R13** (`chart`). The chart adds a checksum of the trusted providers file to the Pod template, so a change of the
  file restarts the Pods.

#### Readiness

- **R14** (`startup`). The agent is ready once it has all of these:
  1. the policy snapshot of every tenant of the policy source (ADR-0093 R17);
  2. a usable key of every provider, the marked provider among them;
  3. a usable key of every realm in `keycloak.requiredRealms`, in every M2M mode;
  4. the default tenant (ADR-0093 R10 to R14).
- **R15** (`keys`). `cloud-common` is the agent's own default for `keycloak.requiredRealms` when the trusted providers
  file holds `keycloak` and names none.
- **R16** (`keys`). A realm outside `keycloak.requiredRealms` loads on the first token that names it and does not affect
  readiness.
- **R17** (`startup`). The 503 of `/ready` names each unmet condition: the provider, the realm, the tenant, or the
  default tenant.
- **R18** (`startup`). Liveness reports only that the process serves requests. It does not depend on keys, policy
  snapshots, tenant-manager, or the agent's token of ADR-0096.
- **R19** (`keys`). Keys that do not arrive do not end the process. The agent retries a required source with pauses of
  up to 10 seconds, logs a warning for each attempt, and stays not ready. The exception is the missing token of ADR-0094
  R5, which stops the start.
- **R20** (`keys`). An agent that became ready stays ready when a later reload fails or leaves a source without keys.

#### Finding a key

- **R21** (`keys`). A key is found by source and then by `kid`, so two realms may publish one `kid`.
- **R22** (`verify`). `kid` is required. A token without it is refused with `TOKEN_KID_MISSING`.
- **R69** (`verify`). A token without `kid` starts no load.
- **R23** (`verify`). A `kid` that matches no key of the source refuses the token with `TOKEN_KID_UNKNOWN` when the
  source answered, as R39 defines. When the keys could not be loaded, R38 applies instead.
- **R24** (`keys`). A key in a JWKS without a `kid` is not loaded, because no token can name it.

#### Reloads

- **R25** (`keys`). The keys of every source are reloaded every hour.
- **R26** (`keys`). The hourly reload has a jitter per source of up to 10 percent.
- **R27** (`keys`). The hourly reload does not count toward the limit of R33.
- **R28** (`keys`). A reload that fails keeps the keys already loaded. A key is removed only when the source returned a
  JWKS without it. A key the agent cannot use counts as absent.
- **R29** (`keys`). A token that finds no key among those loaded starts an on-demand load of its source and of no other
  source. R5, R69, R31, R33, and R37 limit this rule.
- **R70** (`keys`). A realm no token named before loads the same way.
- **R30** (`keys`). The requests that arrive while an on-demand load runs share it.
- **R71** (`keys`). Each of those requests waits at most 3 seconds.
- **R31** (`keys`). A source takes at most one on-demand load a minute. A request within that minute, when no load runs,
  is checked against the keys already loaded and sends no request.
- **R32** (`keys`). A token whose key is loaded never waits.
- **R33** (`keys`). An agent process starts at most 10 on-demand loads a minute over all sources. Past that, a token is
  checked against the keys already loaded.
- **R34** (`keys`). An agent process keeps at most 1000 realms.
- **R35** (`keys`). A realm outside `keycloak.requiredRealms` that never loaded a key is not asked again for a minute,
  and then gives up its place, so names that exist on no Keycloak do not fill the list. The hourly reload of R25 may ask
  it once more within that minute.
- **R36** (`keys`). A realm that loaded keys keeps its place, and a reload that fails leaves its keys, as R28 states.
- **R37** (`keys`). With 1000 realms held, a token of another realm evicts none of them and is refused with
  `TOKEN_KEYS_UNAVAILABLE`.
- **R38** (`verify`). A token that finds no key because its keys could not be loaded is refused with
  `TOKEN_KEYS_UNAVAILABLE`. The keys could not be loaded when the last load of the source failed, the wait of R71 ran
  out, the limit of R33 refused the load, or the list of R34 is full.
- **R39** (`keys`). A source answered when it returned a document with a `keys` array, even an empty one. A 200 with any
  other body is a failed load. A 404 counts as an answer only for a realm with no keys loaded, so a token that names a
  realm the Keycloak does not hold gets `TOKEN_KID_UNKNOWN`. For a realm that holds keys a 404 is a failed reload, and
  the keys stay. A 404 for a provider is no answer.

#### Checks

- **R40** (`verify`). A token that is not a compact JWT, or whose header or payload cannot be parsed, is refused with
  `TOKEN_FORMAT_INVALID`.
- **R41** (`verify`). Only asymmetric algorithms are accepted: RS, PS, and ES with the curve of the algorithm, and EdDSA
  with Ed25519. HMAC, `none`, and any other `alg` are refused with `TOKEN_ALG_NOT_ALLOWED`.
- **R42** (`keys`). An RSA key needs a modulus of at least 2048 bits, and a shorter key is not loaded.
- **R43** (`verify`). A signature that does not verify is refused with `TOKEN_SIGNATURE_INVALID`.
- **R44** (`verify`). `exp` is required, and `nbf` is honored when present, with a leeway of 30 seconds for every token.
  The codes are `TOKEN_EXP_MISSING`, `TOKEN_EXPIRED`, and `TOKEN_NOT_YET_VALID`.
- **R45** (`verify`). `exp` and `nbf` are checked against the time after the key is found, so a token that expires while
  its request waits for a load is refused.
- **R46** (`verify`). `iat` is required, or the token is refused with `TOKEN_IAT_MISSING`.
- **R47** (`verify`). A token whose `exp` comes before its `iat` is refused with `TOKEN_IAT_INVALID`.
- **R48** (`verify`). A Kubernetes token with an `iat` more than 30 seconds in the future is refused with
  `TOKEN_IAT_INVALID`. No other token is refused for a future `iat`.
- **R49** (`verify`). The `aud` of a realm token is not checked.
- **R50** (`verify`). A provider that lists `audiences` matches `aud` exactly against them. A token without `aud` gets
  `TOKEN_AUDIENCE_MISSING` unless the provider sets `allowMissingAud`, and a token that names none of them gets
  `TOKEN_AUDIENCE_INVALID`.
- **R51** (`verify`). `iss` is the one claim read before the signature verifies. Every other claim is read only after
  that.

#### What the verification returns

- **R52** (`handler`). `Incoming-Token` is verified as fully as `Authorization`. The calling service is not trusted to
  have checked it.
- **R53** (`handler`). An empty `Incoming-Token` counts as no header, and nothing is verified.
- **R54** (`verify`). For a token that passes, the verification returns its verified claims whole, as the token carries
  them, its kind, and the result of the M2M test of ADR-0092 R6 to R8 and R21. The kinds are a realm token, a file
  token, and a Kubernetes token.
- **R55** (`verify`). For a token that fails, the verification returns the reason code of the check it failed and no
  claims, so no reader can rely on them.
- **R77** (`verify`). A token that fails several checks gets the code of the first check that runs. The order of the
  checks is the implementer's choice, within R51 and R69.
- **R74** (`verify`). The result of a failed token names its source only when the signature of the token verified.
- **R75** (`keys`). A line in the application log may name the realm in the `iss` of an unverified token, in quotes and
  as text taken from the token.
- **R56** (`verify`). The result holds no token in its compact form.
- **R76** (`handler`). The input of policy evaluation holds no token in its compact form.
- **R57** (`verify`). The verification selects no claims by what a policy declares.
- **R68** (`handler`). Every token is verified in Go against the keys of the trusted issuers before the decision is
  evaluated.

#### The policies and the store

- **R58** (`policy`). The policies do not verify tokens or read keys.
- **R67** (`keys`). The agent writes no keys into the store, and `data.authn` does not exist.

#### The verified-token cache

- **R59** (`verify`). A verified token is cached under the SHA-256 of its compact form until `exp`.
- **R60** (`verify`). A token that a check of this record or ADR-0094 R16 refuses is not cached. A token refused for its
  namespace stays in the cache, because ADR-0094 R22 checks it again.
- **R61** (`verify`). A cached token is returned only while the key that verified it is still loaded for its source, so
  a withdrawn key stops a cached token at once.
- **R62** (`verify`). The cache holds the result of the verification and the claims, and nothing computed for a request.
- **R63** (`verify`). The cache holds at most 10000 tokens and evicts the least recently used one.

#### Settings that go away

- **R64** (`chart`). The settings of the current key loading go away: `AUTHZ_IDP_REALMS`,
  `AUTHZ_JWKS_BOOTSTRAP_REQUIRED`, `AUTHZ_JWKS_HTTP_RETRIES`, `AUTHZ_TRUSTED_PROVIDERS_RELOAD_INTERVAL`, and the
  `required` field of a provider.
- **R65** (`chart`). The values schema refuses those settings, so an installation that still sets `AUTHZ_IDP_REALMS`
  learns that its trust widens.
- **R66** (`keys`). The agent refuses unknown fields of the trusted providers file, so a file that still has `required`
  stops the start with an error that names the field.

### Justification

Verifying in Go puts every token rule in one tested package, and the cache verifies a token once until it expires (R59).
A request with a bad token in `Authorization` is refused before any policy runs, and the policies do not depend on how
keys are fetched (R58).

The operator names where keys come from: the realms of one Keycloak address and the providers of the file (R1, R7).
`iss` selects among them before the signature verifies and grants nothing, because a token can name neither a server nor
a key of its own (R4, R51). A token that names another realm than the one that signed it finds no key there or fails on
its signature, so a token of a tenant cannot pass as a token of `cloud-common`.

Taking the realm from `iss` needs no list of tenants, it lets the agent run without tenant-manager, and the same `kid`
in two realms stops being a conflict (R3, R21).

A realm or a provider signs with a new key as soon as the key is active, so a token that finds no key makes the agent
look again (R29). That is how OpenID Connect Core 1.0, section 10.1.1, and the common clients find a rotated key. The
load is per source, so one unknown `kid` costs one realm rather than every realm. The limits bound what invented tokens
cost Keycloak, because a load happens before any signature is checked (R31, R33 to R35). The hourly reload drops a key
that a source withdrew, and a source that is down keeps its keys, so an outage does not change the answers for keys
already loaded (R25, R28).

Readiness rather than the process keeps traffic away from a Pod without keys (R14, R19): a restart would ask a Keycloak
that is already down, and the Pod would lose what it has loaded. Liveness stays apart for the same reason, because a
probe that followed keys would restart the Pod anyway, with a back-off that delays the recovery (R18).

The jitter keeps the Pods of one rollout from reloading in step (R26).

The cache holds the `Incoming-Token` of every user, and a Kubernetes token stays until an `exp` that its caller chose,
so the bound keeps the memory of a Pod independent of how many tokens it sees (R63).

Verifying `Incoming-Token` means that a service forwards the token as it is, and the agent does not rely on what the
service says about its user (R52). The verification ends at verified claims, so it does not depend on what a policy
declares (R57), and a failed token gives its readers a reason code instead of claims that nothing verified (R55).

### Alternatives considered

- **A1. Keep the checks in Rego.** Rejected by R58: the rules stay split between Go and Rego, and a request with a bad
  token is evaluated before it is refused.
- **A2. List the tenants from tenant-manager and keep one provider per realm.** Rejected by R3: every deployment would
  need tenant-manager, and a `kid` that two realms publish would need a rule of its own. This reverses the choice of the
  meeting of 2026-10-28.
- **A3. Find a key by `kid` alone.** Rejected by R21: nothing makes a `kid` unique across realms.
- **A4. Make `kid` optional and select a key by `x5t` or as the one key of the issuer.** Rejected by R22: Keycloak and
  the API server set `kid` on every token they sign, so the extra selection rules would add code that no token reaches.
  The owner of the policy decision code answered for this option on the questionnaire of 2026-11-03, and this record
  keeps the required `kid` of the questionnaire of 2026-10-19.
- **A5. Stop the start when a required source has no keys.** Rejected by R19: a restart would ask a Keycloak that is
  already down, and the Pod would lose what it has loaded.
- **A6. Reload the keys every 24 hours.** Rejected by R25: a withdrawn key would stay accepted for up to a day.
- **A7. Reload only on the hourly schedule, never on demand.** Rejected by R29: the tokens a rotated key signs would be
  refused for up to an hour.
- **A8. Build the JWKS address of a realm from a fixed path.** Rejected by R4: discovery needs no knowledge of
  Keycloak's paths beyond the address of the realm.
- **A9. Trust the service that sends `Incoming-Token`.** Rejected by R52: a user token that nothing checked would reach
  policy evaluation.
- **A10. Pass the compact token to policy evaluation.** Rejected by R76: a raw credential would reach the input and
  possibly a log.
- **A11. Compute the subject and the TOKEN PIP values in the verification.** Rejected by R57: the verification would
  have to read the PIP declarations of every tenant.

## Consequences

Negative:

- Every realm of the Keycloak is trusted, so an installation that listed a few realms in `AUTHZ_IDP_REALMS` accepts more
  tokens than before.
- Tokens reach Keycloak before any signature is checked. The limits bound the requests, but a stream of invented realms
  can hold all 10 loads, and a realm not loaded yet or a rotated key then waits up to a minute with its tokens refused.
- A Pod that cannot reach Keycloak stays not ready rather than failing, so the signal is the readiness probe and the
  warnings.
- An edit of the trusted providers file outside Helm takes effect only at the next restart of the Pods.
- A provider that signs tokens without `kid` cannot be used, because all its tokens are refused.
- A token without `iat` passes the current policies, and an `iat` up to 300 seconds in the future passes for every
  token. This record refuses a token without `iat`, so a provider that does not set it cannot be used, and it checks a
  future `iat` only for a Kubernetes token.
- The limits of 10 loads a minute and 1000 realms have no measurement behind them. They fit the one or two tenants of
  most production installations. After a restart, a Pod of an installation with more than 10 active realms refuses the
  tokens of the realms past the limit, for about one minute per 10 realms.

Follow-ups:

- When this record is accepted, the status of ADR-0080 names the statements it supersedes.
