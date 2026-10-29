# Verify tokens in Go against the keys of trusted providers

## Status

Proposed

<!-- markdownlint-disable-next-line MD001 -->
#### Date

#### Owner

kichasov

#### Participants and approvers

The project architect, who settled the token rules at two meetings on 2026-10-16 and in a questionnaire returned on
2026-10-19, proposed the hourly key reload at a meeting on 2026-10-23, and at a meeting on 2026-10-28 accepted the
reload on an unknown `kid` and decided that the agent lists the tenants from tenant-manager. The architect approves
this record. The Netcracker/qubership-authz-agent maintainers (kichasov). Assumption: the approvers' GitHub accounts
are added when this record is reviewed.

#### Related ADRs

- [authz-agent-ADR-0080: Replace Envoy, the Lua filters, and the OPA container with one Go service that embeds OPA](20260907-authz-agent-adr-0080-single-go-service-with-embedded-opa.md):
  this record supersedes three of its statements. Under "Handlers instead of Lua", the check routes refuse a missing
  or invalid service token before the policies run, and the policies no longer validate the tokens. Under
  "In-process supporting logic", the JWKS bootstrap no longer writes keys into the store, and the trusted-provider
  reload goes away.

## Context

A check route of the agent receives two tokens: the caller's service token in `Authorization` and, optionally, the
user's token in `Incoming-Token`. Today Go fetches the keys of the trusted providers into the store as `data.authn`,
and `policies/identity.rego` parses and verifies both tokens on every evaluation. The token rules are split between
the Go code that loads keys and the Rego that checks claims, and a request with a bad service token is evaluated
before it is refused. The trusted-provider reload reads the providers file again when its ConfigMap changes, so an
edit takes effect without a restart.

Keycloak names a tenant's realm by a generated identifier and keeps the tenant's name only as the realm's display
name. tenant-manager knows every tenant: `GET /api/v4/tenant-manager/registration/tenants?dns=<name>` returns the
identifier of one tenant as a plain-text body. Tenants are created and removed while the services run. The test stand
runs an emulator of tenant-manager, and the emulator is not published.

The packages `internal/token/keys` and `internal/token/verify` verify tokens in Go and are not wired into the request
path yet.

## Decision

We will verify every token in Go against the keys of the trusted providers before the decision is evaluated. The
policies no longer verify tokens or read keys, and `data.authn` goes away.

### Trusted providers

- The trusted providers file lists the providers: `id`, `issuer` or `jwksUri`, `audiences`, `allowMissingAud`,
  `caFile`, and `tokenFile`.
- The token at a provider's `tokenFile` is sent only with the requests for that provider's discovery document and
  JWKS, and never anywhere else.
- Every provider of the file is required: the agent does not start until it has the keys of each one, retried until a
  startup timeout.
- A key is found by `kid` alone, one key per `kid`, and `iss` is not checked. A `kid` that two providers of the file
  publish stops the start.
- The agent reads the providers file at start, and the chart restarts the Pods when it changes.

### Tenant realms

- The agent lists the tenants from tenant-manager, at `tenantManagerUrl`, at start and again every 30 seconds. It
  keeps one provider for the realm of each tenant, at the realm identifier under the Keycloak address the providers
  file names for tenant realms. Assumption: the list is `GET /api/v4/tenant-manager/manage/tenants`.
- A tenant that leaves the list loses its realm at the next listing. While tenant-manager does not answer, the agent
  keeps the list it has, as it keeps the keys of a provider that does not answer.
- The realm of a tenant created after the start is found at the next listing. A token of it whose `kid` the agent
  does not know yet triggers the reload on an unknown `kid`.

### Reloads

- The keys of every provider, tenant realms included, are reloaded every hour and at a restart.
- A token whose `kid` no loaded key has triggers a reload of every provider. The requests that arrive while that
  reload runs wait for it and share it. Such reloads start at most once a minute per Pod: a request that arrives
  within that minute, when no reload runs, gets `TOKEN_KID_UNKNOWN` at once and no request is sent. A request whose
  `kid` is known never waits.
- A `kid` still unknown after the reload is refused with `TOKEN_KID_UNKNOWN`.
- A provider that does not answer during a reload keeps the keys already loaded for it. When the new keys of two
  providers share a `kid`, nothing is replaced and every provider keeps its previous keys.

### Checks

- Only asymmetric algorithms are accepted: RS, PS, and ES with the curve of the algorithm, and EdDSA with Ed25519. An
  RSA key needs a modulus of at least 2048 bits.
- `kid`, `exp`, and `iat` are required, and `nbf` is honored, with a leeway of 30 seconds. They are checked against
  the time after the key is found, so a token that expires while its request waits for a reload is refused.
- `aud` is matched exactly against the provider's `audiences` when the provider lists any. Keycloak providers list
  none.
- A token that fails a check is refused with 401 and the `TOKEN_*` reason code of that check.

### The verified-token cache

- A verified token is cached under the SHA-256 of its compact form until `exp`; a refusal is not cached.
- A cached token is returned only while the key that verified it is still loaded under its `kid`, so a withdrawn key
  or a removed tenant realm stops a cached token at once.
- The cache holds the result of the verification and the claims, and nothing computed for a request.

### Justification

Verifying in Go puts every token rule in one tested package, and the cache verifies a token once until it expires. A
request with a bad service token is refused before any policy runs, and the policies do not depend on how keys are
fetched.

The operator names the sources of keys: the providers of the file, and the Keycloak address under which the realms of
the listed tenants are found. The `kid` of a token selects a key among them and `iss` plays no part, so a token can
bring neither a key nor an issuer of its own.

A provider signs with a new key as soon as the key is active, so the first token that names an unknown `kid` makes the
agent look again. That is how OpenID Connect Core 1.0, section 10.1.1, and the common clients find a rotated key. One
shared reload at most once a minute bounds what an invented `kid` costs: one request per provider and Pod a minute,
and only to the addresses of the configuration. The hourly reload drops a key that a provider withdrew. A provider
that is down during a reload keeps the keys already loaded, so a reload does not stop the agent.

Listing the tenants follows tenants that appear and disappear while the agent runs, with no restart. Keeping the last
list while tenant-manager is down follows the rule the agent applies to keys.

Alternatives considered:

- **Keep the checks in Rego.** Rejected: the rules stay split between Go and Rego, and a request with a bad service
  token is evaluated before it is refused.
- **Reload the keys every 24 hours.** Rejected: a rotated key would be unknown for up to a day.
- **Reload only on the hourly schedule, never on an unknown `kid`.** Rejected: the tokens a rotated key signs would be
  refused for up to an hour.
- **Trust any realm of the configured Keycloak, found by the `iss` of the token.** Rejected: it brings back the check
  of `iss` and changes the providers file.
- **Add the realm of a new tenant to the providers file and restart the Pods.** Rejected: tenants appear while the
  agent runs.

## Consequences

Positive:

- The store holds no keys.
- The token rules have one implementation with unit tests.
- The first token signed by a key a provider rotated in makes the agent find that key, unless a reload on an unknown
  `kid` started in the minute before.
- A new tenant's tokens are accepted within about 90 seconds of its creation, with no restart: up to 30 seconds until
  the next listing, and up to a minute more when a token of the tenant spent the reload before the listing added its
  realm.

Negative:

- A token with an invented `kid` makes the agent reload the keys of every provider, the realm of every tenant
  included, at most once a minute per Pod, and the requests that wait for that reload wait for the slowest provider.
- A provider of the file that cannot be reached stops the start. The chart's default realms are `cloud-common`,
  `default`, `cpq`, and `external`, so an installation without one of them has to remove it from the list.
- A `kid` that two providers publish after the start keeps the previous keys of every provider, so it stops the
  rotation of all of them. The chart lists the realm `default`, and the same realm can also arrive from the
  tenant-manager listing.
- An edit of the trusted providers ConfigMap outside Helm takes effect only at the next restart of the Pods.

Neutral:

- When this record is accepted, the status of ADR-0080 names the three statements it supersedes.
- `internal/token/keys` reloads every hour instead of every 24 hours and gains the reload on an unknown `kid`, and
  `verify.KeyFinder` gains a lookup that can wait for that reload. The listing replaces the one-time resolution of a
  named tenant that #121 adds.
- The chart settings of the current key loading go away: `AUTHZ_JWKS_BOOTSTRAP_REQUIRED`, `AUTHZ_JWKS_HTTP_RETRIES`,
  `AUTHZ_TRUSTED_PROVIDERS_RELOAD_INTERVAL`, and the `required` field of a provider. The chart adds a checksum of the
  trusted providers file to the Pod template so that a change restarts the Pods, and `AUTHZ_TENANT_MANAGER_URL`
  becomes `tenantManagerUrl`. The documentation page of the trusted providers file, which the wiring change adds,
  describes them.
- The tenant-manager emulator of the test stand gains the list of tenants.
- Later the realms of tenants may come from a custom resource of the identity provider's operator, once it exists.
- Open points, decided as above until answered:
  - whether the keys of tenant realms are required at start, like the providers of the file;
  - how a `kid` that two providers publish after the start is handled, so that it does not stop the rotation of
    every provider;
  - a timeout for the wait for a reload, inside the latency budget of a check;
  - a deployment without tenant-manager, where the listing is off and tenant realms come from the providers file only;
  - the tenant-manager request that lists the tenants, and how the providers file names the Keycloak address of tenant
    realms.
