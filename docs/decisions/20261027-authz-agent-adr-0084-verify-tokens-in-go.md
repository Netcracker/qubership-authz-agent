# Verify tokens in Go before OPA and pass the policies the verified identity

## Status

Proposed

<!-- markdownlint-disable-next-line MD001 -->
#### Date

#### Owner

kichasov

#### Participants and approvers

The project architect, who settled the token rules at two meetings on 2026-10-16 and in a questionnaire returned on
2026-10-19, and proposed the hourly key reload at a meeting on 2026-10-23. The owner of the policy decision code, who
chose on 2026-10-27 that Go passes ready fields, the values of TOKEN PIPs among them, and that a refusal before OPA is
logged as an event without a policy evaluation. The Netcracker/qubership-authz-agent maintainers (kichasov).
Assumption: the approvers' GitHub accounts are added when this record is reviewed.

#### Related ADRs

- [authz-agent-ADR-0080: Replace Envoy, the Lua filters, and the OPA container with one Go service that embeds OPA](20260907-authz-agent-adr-0080-single-go-service-with-embedded-opa.md):
  this record supersedes three of its statements. Under "Handlers instead of Lua", the check routes refuse a missing
  or invalid service token before the policies run, and the policies no longer validate the tokens. Under
  "In-process supporting logic", the JWKS bootstrap no longer writes keys into the store, and the trusted-provider
  reload goes away.
- [authz-agent-ADR-0085: Take the tenant of a decision from the request and check the caller against it](20261027-authz-agent-adr-0085-tenant-from-the-request.md):
  the tenant this record passes to OPA, and the caller check that runs before OPA.
- [authz-agent-ADR-0086: Accept Kubernetes service account tokens from the namespaces of the installation](20261027-authz-agent-adr-0086-kubernetes-service-account-tokens.md):
  the Kubernetes provider, the namespace check that runs in this record's verifier, and the M2M mode that decides which
  service tokens `Authorization` accepts.

## Context

A check route of the agent receives two tokens: the caller's service token in `Authorization` and, optionally, the
user's token in `Incoming-Token`. Today Go fetches the keys of the trusted providers into the store as `data.authn`,
and `policies/identity.rego` parses and verifies both tokens on every evaluation. The token rules are split between
the Go code that loads keys and the Rego that checks claims, and a request with a bad service token is evaluated
before it is refused.

From a verified token, `policies/identity.rego` builds a subject of `id`, `name`, `type`, `roles`, and `scopes`, and
`policies/pip.rego` reads the claim a TOKEN PIP names from the token payload. Go writes the decision log. The
trusted-provider reload reads the providers file again when its ConfigMap changes, so an edit takes effect without a
restart.

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
- The keys are reloaded every hour and at a restart. A token whose `kid` no provider publishes is refused with
  `TOKEN_KID_UNKNOWN`, and no provider is asked for it.
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
  accepts. An M2M token is a Keycloak token with a `level` of `m2m` or `key-manager` in any case, or with the role
  `ROLE_M2M` in any realm, or a Kubernetes token. The mode `legacy` accepts the Keycloak ones, `hybrid` both kinds, and
  `k8s` Kubernetes tokens only.
- A missing or invalid service token, and one of a kind the mode does not accept, is refused with 401 before OPA. The
  caller check of ADR-0085 then runs, also before OPA, and refuses with 403.
- A user token that fails verification does not end the request. The request reaches OPA with the code of the
  failure, and the policies deny it with 200.
- With `Authorization-Type: anonymous` the subject is the anonymous user, and a user token is ignored, as it is today.
  Without that header the subject is the user token, or the service token when there is no user token.

### The identity OPA receives

Go computes and passes:

- the subject, with the `id`, `name`, `type`, `roles`, and `scopes` that `policies/identity.rego` builds today;
- the tenant of the request, by the rule of ADR-0085;
- the `level`;
- the id of the provider whose key verified the token;
- whether the request is anonymous;
- for a user token that failed, the `verify` code;
- the value and the state of every TOKEN PIP. Go reads the value from the verified token by the claim or the jsonPath
  the PIP configuration names and applies its `defaultValue`. The token payload itself is not passed.

The owner of the policy decision code changes `policies/identity.rego` to read these fields. Assumption: the field
names and their place in `input` are settled with that owner before the wiring change.

### Errors and the decision log

The 401 body carries `reasonCode` next to `message`. The codes are `TOKEN_MISSING`, `TOKEN_SCHEME_INVALID`,
`TOKEN_FORMAT_INVALID`, `TOKEN_ALG_NOT_ALLOWED`, `TOKEN_KID_MISSING`, `TOKEN_KID_UNKNOWN`, `TOKEN_SIGNATURE_INVALID`,
`TOKEN_AUDIENCE_MISSING`, `TOKEN_AUDIENCE_INVALID`, `TOKEN_EXP_MISSING`, `TOKEN_EXPIRED`, `TOKEN_NOT_YET_VALID`,
`TOKEN_IAT_MISSING`, `TOKEN_IAT_INVALID`, and `TOKEN_NAMESPACE_NOT_ALLOWED`. A service token that is not M2M, or of
a kind the mode does not accept, gets a code of its own. Assumption: `TOKEN_NOT_M2M`.

With the decision log on, every request has an event, written by the code that writes the events today. A refusal
before OPA, a 401 of this record or a 403 of the caller check of ADR-0085, is an event without a policy evaluation.
Every event carries the `reasonCode`, the provider id, the tenant of the request, and the `X-Request-Id` of the
request.

The token the agent sends to PIPs is a decision of its own and is not part of this record.

### Justification

Verifying in Go puts every token rule in one tested package, and the cache verifies a token once until it expires. A
request with a bad service token is refused before any policy runs. The policies receive a fixed identity, the values
of TOKEN PIPs included, and do not depend on how keys are fetched or how a claim is read.

The operator names every source of keys in the providers file. The `kid` of a token selects a key among them and `iss`
plays no part, so a token can bring neither a key nor an issuer of its own.

The hourly reload finds a key that a provider rotated in, and drops one it withdrew, within an hour. A provider that is
down during a reload keeps the keys already loaded, so the reload does not stop the agent.

The decision log and the error body keep one implementation each: Go already writes every event and wraps every 401,
so a refusal before OPA uses the same code.

Alternatives considered:

- **Keep the checks in Rego.** Rejected: the rules stay split between Go and Rego, and a request with a bad service
  token is evaluated before it is refused.
- **Verify in Go and pass the token payload to Rego.** Rejected: the policies would compute the subject and the TOKEN
  PIP values again, so the rules would still live in two places.
- **Reload the keys every 24 hours.** Rejected: a rotated key would be unknown for up to a day, and the architect
  proposed the hourly reload.
- **Reload the keys of every provider when a token names an unknown `kid`, at most once a minute.** Open: it finds a
  rotated key at once and is how OpenID Connect Core 1.0, section 10.1.1, and the common clients find one, but the
  architect is against any request to a provider on an unknown `kid`.

## Consequences

Positive:

- The policies read the identity, and the store holds no keys.
- The token rules have one implementation with unit tests.

Negative:

- The Go wiring and the change to `policies/identity.rego` have to land together.
- The current policies accept any valid token in `Authorization`. After this change a user token there is refused,
  unless the open point of ADR-0085 on user tokens admits it.
- A key that a provider rotates in is unknown until the next hourly reload or a restart, so the tokens it signs are
  refused for up to an hour.
- A provider that cannot be reached stops the start. The chart's default realms are `cloud-common`, `default`, `cpq`,
  and `external`, so an installation without one of them has to remove it from the list.
- An edit of the trusted providers ConfigMap outside Helm takes effect only at the next restart of the Pods.

Neutral:

- When this record is accepted, the status of ADR-0080 names the three statements it supersedes.
- `internal/token/keys` reloads every hour instead of every 24 hours.
- The decision log event gains the `reasonCode` and the provider id.
- The chart settings of the current key loading go away: `AUTHZ_JWKS_BOOTSTRAP_REQUIRED`, `AUTHZ_JWKS_HTTP_RETRIES`,
  `AUTHZ_TRUSTED_PROVIDERS_RELOAD_INTERVAL`, and the `required` field of a provider. The chart adds a checksum of the
  trusted providers file to the Pod template so that a change restarts the Pods.
- Open point, decided as above until answered: whether a token with an unknown `kid` triggers a reload limited in
  rate. It awaits the architect.
