# Verify tokens in Go before OPA and pass the policies the verified identity

## Status

Proposed

<!-- markdownlint-disable-next-line MD001 -->
#### Date

#### Owner

kichasov

#### Participants and approvers

The project architect, who settled the token rules at two meetings on 2026-10-16 and in a questionnaire returned on
2026-10-19. The owner of the policy decision code, who chose on 2026-10-27 that Go passes ready fields and that the
code of a refusal reaches the 401 body and the decision log. The Netcracker/qubership-authz-agent maintainers
(kichasov). Assumption: the approvers' GitHub accounts are added when this record is reviewed.

#### Related ADRs

- [authz-agent-ADR-0080: Replace Envoy, the Lua filters, and the OPA container with one Go service that embeds OPA](20260907-authz-agent-adr-0080-single-go-service-with-embedded-opa.md):
  this record supersedes three of its statements. Under "Handlers instead of Lua", the check routes refuse a missing
  or invalid service token before the policies run, and the policies no longer validate the tokens. Under
  "In-process supporting logic", the JWKS bootstrap no longer writes keys into the store, and the trusted-provider
  reload goes away.
- [authz-agent-ADR-0085: Compute the tenant in Go from the verifying provider](20261027-authz-agent-adr-0085-tenant-from-the-verifying-provider.md):
  the tenant this record passes to OPA.
- [authz-agent-ADR-0086: Accept Kubernetes service account tokens from the namespaces of the installation](20261027-authz-agent-adr-0086-kubernetes-service-account-tokens.md):
  the Kubernetes provider, the namespace check that runs in this record's verifier, and the M2M mode that decides which
  service tokens `Authorization` accepts.

## Context

A check route of the agent receives two tokens: the caller's service token in `Authorization` and, optionally, the
user's token in `Incoming-Token`. Today Go fetches the keys of the trusted providers into the store as `data.authn`,
and `policies/identity.rego` parses and verifies both tokens on every evaluation. The token rules are split between
the Go code that loads keys and the Rego that checks claims, and a request with a bad service token is evaluated
before it is refused.

From a verified token, `policies/identity.rego` builds a subject of `id`, `name`, `type`, `roles`, and `scopes`. A
TOKEN PIP reads the claim its configuration names from the token payload. The trusted-provider reload reads the
providers file again when its ConfigMap changes, so an edit takes effect without a restart.

The packages `internal/token/keys` and `internal/token/verify` verify tokens in Go and are not wired into the request
path yet.

## Decision

We will verify both tokens in Go before the decision is evaluated, and pass OPA the verified identity. The policies
no longer verify tokens or read keys, and `data.authn` goes away.

### Trusted providers

- The trusted providers file lists every provider: `id`, `issuer` or `jwksUri`, `audiences`, `allowMissingAud`,
  `caFile`, and `tokenFile`. ADR-0085 adds `tenantRealm` and `tenantManagerUrl`, and ADR-0086 adds `kubernetes`.
- Every provider is required: the agent does not start until it has the keys of each one, retried until a startup
  timeout.
- A key is found by `kid` alone, one key per `kid`, and `iss` is not checked. A `kid` that two providers publish stops
  the start.
- The keys are reloaded every hour and at a restart. A token whose `kid` no provider publishes triggers a reload of
  every provider: the requests that wait for it share one reload, and reloads run at most once a minute.
- The list of providers is fixed per installation. The agent reads the file at start, and the chart restarts the Pods
  when it changes.

### Checks

- Only asymmetric algorithms are accepted: RS, PS, and ES with the curve of the algorithm, and EdDSA with Ed25519. An
  RSA key needs a modulus of at least 2048 bits.
- `kid`, `exp`, and `iat` are required, and `nbf` is honored, with a leeway of 30 seconds.
- `aud` is matched exactly against the provider's `audiences` when the provider lists any. Keycloak providers list
  none.
- A verified token is cached under its SHA-256 until `exp`; a refusal is not cached.

### Requests

- `Authorization` is required on the check routes and has to carry an M2M token of a kind the M2M mode of ADR-0086
  accepts. A Keycloak M2M token is a token with a `level` of `m2m`, `key-manager`, or `external`, or with the role
  `ROLE_M2M`. The mode `legacy` accepts Keycloak M2M tokens, `hybrid` accepts them and Kubernetes tokens, and `k8s`
  accepts Kubernetes tokens only.
- A missing or invalid service token, and one of a kind the mode does not accept, is refused with 401 before OPA.
- A user token that fails verification does not end the request. The request reaches OPA with the code of the
  failure, and the policies deny it with 200.
- With `Authorization-Type: anonymous` the subject is the anonymous user, and a user token is ignored, as it is today.
  Without that header the subject is the user token, or the service token when there is no user token.

### The identity OPA receives

Go computes and passes:

- the subject, with the `id`, `name`, `type`, `roles`, and `scopes` that `policies/identity.rego` builds today;
- the `tenant`, by the rule of ADR-0085;
- the `level`;
- the id of the provider whose key verified the token;
- whether the request is anonymous;
- for a user token that failed, the `verify` code.

The owner of the policy decision code changes `policies/identity.rego` to read these fields. Assumption: the field
names and their place in `input` are settled with that owner before the wiring change.

### Errors

The 401 body carries `reasonCode` next to `message`, and the decision log carries it for every request that reaches
OPA, together with the provider id. The codes are `TOKEN_MISSING`, `TOKEN_SCHEME_INVALID`, `TOKEN_FORMAT_INVALID`,
`TOKEN_ALG_NOT_ALLOWED`, `TOKEN_KID_MISSING`, `TOKEN_KID_UNKNOWN`, `TOKEN_SIGNATURE_INVALID`,
`TOKEN_AUDIENCE_MISSING`, `TOKEN_AUDIENCE_INVALID`, `TOKEN_EXP_MISSING`, `TOKEN_EXPIRED`, `TOKEN_NOT_YET_VALID`,
`TOKEN_IAT_MISSING`, `TOKEN_IAT_INVALID`, and `TOKEN_NAMESPACE_NOT_ALLOWED`. A service token that is not M2M, or of
a kind the mode does not accept, gets a code of its own. Assumption: `TOKEN_NOT_M2M`.

The token the agent sends to PIPs is a decision of its own and is not part of this record.

### Justification

Verifying in Go puts every token rule in one tested package, and the cache verifies a token once until it expires. A
request with a bad service token is refused before any policy runs. The policies receive a fixed identity and do not
depend on how keys are fetched.

The operator names every source of keys in the providers file. The `kid` of a token selects a key among them and `iss`
plays no part, so a token can bring neither a key nor an issuer of its own.

A new key signs Keycloak tokens as soon as it becomes active, so the agent has to find a key it does not know when a
token names it. A reload on an unknown `kid`, limited in rate and shared by the requests that wait, is how OpenID
Connect Core 1.0, section 10.1.1, and the common clients find a rotated key. The hourly reload removes a key that a
provider withdrew.

Alternatives considered:

- **Keep the checks in Rego.** Rejected: the rules stay split between Go and Rego, and a request with a bad service
  token is evaluated before it is refused.
- **Verify in Go and pass the token's claims to Rego.** Rejected: the policies would compute the subject and the
  tenant again, so the rules would still live in two places.
- **Reload the keys every 24 hours, never on an unknown `kid`, and restart the Pods after a key rotation.** Rejected
  in this proposal: until a restart, the tokens signed by a rotated key are refused for up to 24 hours, and a key that
  a provider withdrew stays accepted as long. The architect chose this first and has not answered the proposal yet.

## Consequences

Positive:

- The policies read the identity, and the store holds no keys.
- The token rules have one implementation with unit tests.

Negative:

- The Go wiring and the change to `policies/identity.rego` have to land together.
- The current policies accept any valid token in `Authorization`. A caller that sends a user token there is refused
  after this change.
- A provider that cannot be reached stops the start. The chart's default realms are `cloud-common`, `default`, `cpq`,
  and `external`, so an installation without one of them has to remove it from the list.
- An edit of the trusted providers ConfigMap outside Helm takes effect only at the next restart of the Pods.
- A request with a bad service token leaves no decision log event, so a test that reads the reason of such a refusal
  from the log reads it from the response instead.
- A token with an invented `kid` makes the agent reload the keys of every provider, at most once a minute per Pod.

Neutral:

- When this record is accepted, the status of ADR-0080 names the three statements it supersedes.
- `internal/token/keys` reloads every hour instead of every 24 hours and gains the reload on an unknown `kid`, and
  `verify.KeyFinder` gains a lookup that can wait for that reload.
- The chart settings of the current key loading go away: `AUTHZ_JWKS_BOOTSTRAP_REQUIRED`, `AUTHZ_JWKS_HTTP_RETRIES`,
  `AUTHZ_TRUSTED_PROVIDERS_RELOAD_INTERVAL`, and the `required` field of a provider. The chart adds a checksum of the
  trusted providers file to the Pod template so that a change restarts the Pods.
- Open points, decided as above until answered:
  - the reload on an unknown `kid` and the hourly reload, which await the architect's answer;
  - whether `input` also carries the verified payload, since a TOKEN PIP reads a claim that the fields above may not
    contain, such as `azp` or `email`;
  - where a refusal before OPA is recorded: an event in the decision log without a policy evaluation, or a log line
    and a metric;
  - the agent's own token in the mode `hybrid`: a Kubernetes token with a fallback to a Keycloak token when the
    Kubernetes one is refused, which `internal/token/outbound` does not have. That belongs to the decision on the
    agent's own token.
