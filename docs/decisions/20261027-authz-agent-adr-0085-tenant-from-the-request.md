# Take the tenant of a decision from the request and check the caller against it

## Status

Proposed

<!-- markdownlint-disable-next-line MD001 -->
#### Date

#### Owner

kichasov

#### Participants and approvers

The project architect, who decided at two meetings on 2026-10-16 and in a questionnaire returned on 2026-10-19 that Go
computes the tenant and that a tenant realm is found through tenant-manager. The owner of the policy decision code, who
decided on 2026-10-21 where the tenant of a decision comes from and how the caller is checked against it, and confirmed
it on 2026-10-27. The Netcracker/qubership-authz-agent maintainers (kichasov). Assumption: the approvers' GitHub
accounts are added when this record is reviewed.

#### Related ADRs

- [authz-agent-ADR-0084: Verify tokens in Go before OPA and pass the policies the verified identity](20261027-authz-agent-adr-0084-verify-tokens-in-go.md):
  the tenant is one of the fields that record passes to OPA, and the caller check of this record runs before OPA there.
- [authz-agent-ADR-0086: Accept Kubernetes service account tokens from the namespaces of the installation](20261027-authz-agent-adr-0086-kubernetes-service-account-tokens.md):
  which tokens are Kubernetes tokens.

## Context

A check route receives a tenant from its caller in two places: the `tenant_id` query parameter and the `Tenant`
header. The calling service computes the tenant of its own request and sends it in both. The current policies do not
read a tenant, and the architect decided that Go computes one and passes it to OPA with the rest of the identity.

The parity cases of #42 for tenants take the tenant from `tenant_id` or from the `Tenant` header, also when the user
token names another tenant: `t3-query-names-other-tenant` and `t4-header-names-other-tenant` let a user of tenant B
ask about data of tenant A through a service with an M2M token.

Keycloak names a tenant's realm by a generated identifier and keeps the tenant's name only as the realm's display
name. tenant-manager maps a tenant's name to the identifier:
`GET /api/v4/tenant-manager/registration/tenants?dns=<name>` returns it as a plain-text body. The test stand runs an
emulator of that request, and the emulator is not published.

## Decision

We will take the tenant of a decision from the request, check the service token against it before OPA, and pass the
tenant to OPA.

### The tenant of a decision

- The tenant is the non-empty `tenant_id`, else the non-empty `Tenant` header, else the default tenant. A token never
  sets it.
- The default tenant is a chart setting that holds a tenant's display name, `default` by default. Assumption: the
  setting is named `AUTHZ_DEFAULT_TENANT`. The agent resolves the name to the realm identifier through tenant-manager at
  start and serves no decision until it has.
- A non-empty tenant that the policy data does not know gets a deny.

### The caller check

Before OPA, the token in `Authorization` passes when one of these holds:

- its claim `tenant-id` equals the tenant of the request;
- it has no claim `tenant-id`, and the request goes to the default tenant;
- it is an M2M token, as ADR-0084 defines one.

Otherwise the request is refused with 403 before OPA and logged as ADR-0084 logs a refusal before OPA.

A switch, off by default, also checks the user token: when the token in `Incoming-Token` carries `tenant-id`, the
claim is compared with the tenant of the request. A mismatch is logged as a warning, and with the switch on it is
refused with 403.

### Tenant realms

A provider that sets `tenantRealm: true` names the tenant in the last path segment of its `issuer`, and the top-level
`tenantManagerUrl` names tenant-manager. At start the agent asks tenant-manager for the realm identifier of each such
tenant, retrying until it gets an acceptable answer, and loads that realm's keys under the identifier.

### Justification

The calling service is the one that knows for which tenant it asks, and the parity cases of #42 take the tenant from
the request in the same way. A tenant computed from the token would answer those cases differently, and a user of one
tenant could no longer reach another tenant's data through a service that names it.

The caller check keeps a direct call with a user token in its own tenant, while a service with an M2M token may name
any tenant.

The default tenant gives every request a tenant, and a deployment names which one. Resolving it at start keeps a
misspelled or unknown default from denying every request of the default tenant without a word.

Alternatives considered:

- **Compute the tenant of a decision from the token, by the rule the calling services use.** Rejected: the services
  already apply that rule and send its result, and the parity cases of #42 would get other answers.
- **Ignore `tenant_id`.** Rejected: a request that names its tenant only in `tenant_id` would go to the default
  tenant.
- **Check the user token against the tenant of the request by the rule the calling services use.** Open: it would also
  refuse a token of the realm `external` without `tenant-id`, which otherwise reaches the default tenant. It is to be
  settled with the architect.

## Consequences

Positive:

- The tenant has one source, the request, and the policies receive it ready.
- A direct call with a user token cannot name a tenant other than its own.

Negative:

- A service with an M2M token decides the tenant of its user's request, so a user can reach another tenant's data
  through a service that names it.
- A token of the realm `external` without the claim `tenant-id` reaches the default tenant, until the check of the user
  token is settled.
- Every tenant realm and the default tenant need tenant-manager at start: until it answers, the agent serves no
  decision.

Neutral:

- `internal/token/keys` resolves tenant realms through tenant-manager, as #121 adds.
- The chart renders `tenantRealm`, `tenantManagerUrl`, and the default tenant, and `AUTHZ_TENANT_MANAGER_URL` becomes
  `tenantManagerUrl`. The documentation page of the trusted providers file, which the wiring change adds, describes
  them.
- An installation outside the cloud needs a published tenant-manager emulator.
- Open points, decided as above until answered:
  - whether the user token is also checked against the tenant of the request by the rule the calling services use, as
    a warning and with a switch a 403; to be settled at a joint meeting with the architect;
  - whether `Authorization` accepts a user token at all: the caller check admits one in its own tenant, while ADR-0084
    records the architect's answer that only an M2M token is a service token;
  - the reason codes of the 403 of the caller check, which the token library does not have yet;
  - how a tenant realm created after the start reaches the trusted providers, since the list is read at start.
