# Take the tenant of a decision from the request and check the user token against it

## Status

Proposed

<!-- markdownlint-disable-next-line MD001 -->
#### Date

#### Owner

kichasov

#### Participants and approvers

The project architect, who decided at two meetings on 2026-10-16 and in a questionnaire returned on 2026-10-19 that Go
computes the tenant and that a tenant realm is found through tenant-manager, and at a meeting on 2026-10-28 settled the
check of the user token and that the agent lists the tenants from tenant-manager. The owner of the policy decision
code, who decided on 2026-10-21 where the tenant of a decision comes from, and confirmed it on 2026-10-27. The
Netcracker/qubership-authz-agent maintainers (kichasov). Assumption: the approvers' GitHub accounts are added when this
record is reviewed.

#### Related ADRs

- [authz-agent-ADR-0084: Verify tokens in Go before OPA and pass the policies the verified identity](20261027-authz-agent-adr-0084-verify-tokens-in-go.md):
  the tenant is one of the fields that record passes to OPA, `Authorization` carries only an M2M token there, and the
  check of this record runs before OPA there.
- [authz-agent-ADR-0086: Accept Kubernetes service account tokens from the namespaces of the installation](20261027-authz-agent-adr-0086-kubernetes-service-account-tokens.md):
  which tokens are Kubernetes tokens.

## Context

A check route receives a tenant from its caller in two places: the `tenant_id` query parameter and the `Tenant`
header. The calling service computes the tenant of its own request by a rule of its own and sends it in both. The
current policies do not read a tenant, and the architect decided that Go computes one and passes it to OPA with the
rest of the identity.

The parity cases of #42 for tenants take the tenant from `tenant_id` or from the `Tenant` header, also when the user
token names another tenant: `t3-query-names-other-tenant` and `t4-header-names-other-tenant` let a user of tenant B
ask about data of tenant A through a service with an M2M token.

Keycloak names a tenant's realm by a generated identifier and keeps the tenant's name only as the realm's display
name. tenant-manager knows every tenant: `GET /api/v4/tenant-manager/registration/tenants?dns=<name>` returns the
identifier of one tenant as a plain-text body. Tenants are created and removed while the services run. The test stand
runs an emulator of tenant-manager, and the emulator is not published.

## Decision

We will take the tenant of a decision from the request, check the user token against it before OPA, and pass the
tenant to OPA.

### The tenant of a decision

- The tenant is the non-empty `tenant_id`, else the non-empty `Tenant` header, else the default tenant. A token never
  sets it.
- The default tenant is a chart setting that holds a tenant's display name, `default` by default. Assumption: the
  setting is named `AUTHZ_DEFAULT_TENANT`. The agent resolves the name to the realm identifier through tenant-manager at
  start and serves no decision until it has.
- A non-empty tenant that the policy data does not know gets a deny.
- `Authorization` carries only an M2M token (ADR-0084), and the service token is not checked against the tenant: a
  service with an M2M token may name any tenant.

### The check of the user token

When the request carries a user token in `Incoming-Token`, Go computes the tenant of that user by the rule the calling
services use, and compares it with the tenant of the request:

| User token | Tenant of the user |
| --- | --- |
| A token of `cloud-common` that is a cloud-level caller | The `Tenant` header; empty without it |
| A token of `external` | The claim `tenant-id`; empty without it |
| A token of any other provider | The realm of its provider: the identifier of a tenant realm, the provider id otherwise |

A token of `cloud-common` is a cloud-level caller when it has the role `ROLE_CLOUD-ADMIN` or `ROLE_M2M`, or a `level`
of `m2m` or `key-manager` in any case, or of `external`.

A mismatch is logged as a warning that names both tenants. With a switch on, off by default, the request is refused
before OPA. Assumption: the refusal is a 400 with the reason code `INCOMING_TENANT_MISMATCH`.

### Tenant realms

- The agent lists the tenants from tenant-manager at start and again every 30 seconds, and keeps one provider for the
  realm of each tenant, at the realm identifier under the Keycloak address the providers file names for tenant realms,
  with `tenantManagerUrl`. Assumption: the list is `GET /api/v4/tenant-manager/manage/tenants`.
- A tenant that leaves the list loses its realm at the next listing. While tenant-manager does not answer, the agent
  keeps the list it has, as it keeps the keys of a provider that does not answer.
- The realm of a tenant created after the start is found at the next listing, and a token of it with a `kid` the agent
  does not know yet triggers the reload of ADR-0084 like any other.

### Justification

The calling service is the one that knows for which tenant it asks, and the parity cases of #42 take the tenant from
the request in the same way. A tenant computed from the token would answer those cases differently, and a user of one
tenant could no longer reach another tenant's data through a service that names it.

A verified token is worth more than a header, and a header only counts when a known service sends it. With an M2M
token in `Authorization` the service is known, so its tenant stands, and the user token is compared with it: a
contradiction shows up as a warning, or as a refusal with the switch on. A token of `external` without `tenant-id` has
an empty tenant, so the check catches it too. A request that names a tenant its own user token contradicts is invalid
input rather than a denial, which is why the refusal is a 400 and not a 403.

The default tenant gives every request a tenant, and a deployment names which one. Resolving it at start keeps a
misspelled or unknown default from denying every request of the default tenant without a word.

Listing the tenants follows tenants that appear and disappear while the agent runs, with no restart. Keeping the last
list while tenant-manager is down follows the rule the agent applies to keys.

Alternatives considered:

- **Compute the tenant of a decision from the token, by the rule the calling services use.** Rejected: the services
  already apply that rule and send its result, and the parity cases of #42 would get other answers.
- **Ignore `tenant_id`.** Rejected: a request that names its tenant only in `tenant_id` would go to the default
  tenant.
- **Check only the claim `tenant-id` of the user token.** Rejected: a token of `external` without the claim would
  reach the default tenant unnoticed.
- **Trust any realm of the configured Keycloak, found by the `iss` of the token.** Rejected: it brings back the check
  of `iss` and changes the providers file.
- **Add the realm of a new tenant to the providers file and restart the Pods.** Rejected: tenants appear while the
  agent runs.

## Consequences

Positive:

- The tenant has one source, the request, and the policies receive it ready.
- A user token that contradicts the tenant its service names shows up in the log, and can be refused.
- A new tenant's tokens are accepted within 30 seconds of its creation, with no restart.

Negative:

- A service with an M2M token can ask about any tenant. This is accepted: the architect holds that authorization data
  is not secret.
- While the switch is off, a token of `external` without `tenant-id` reaches the tenant its service names, the default
  tenant included, with only a warning.
- tenant-manager has to answer at start: until it does, the default tenant is unknown and the agent serves no
  decision.

Neutral:

- `internal/token/keys` lists the tenant realms from tenant-manager and refreshes them, in place of the one-time
  resolution of a named tenant that #121 adds.
- The chart renders `tenantManagerUrl`, the Keycloak address of tenant realms, the default tenant, and the switch, and
  `AUTHZ_TENANT_MANAGER_URL` becomes `tenantManagerUrl`. The documentation page of the trusted providers file, which
  the wiring change adds, describes them.
- The tenant-manager emulator of the test stand gains the list of tenants, and an installation outside the cloud needs
  a published emulator.
- Later the realms of tenants may come from a custom resource of the identity provider's operator, once it exists.
- Open points, decided as above until answered:
  - the status of the refusal with the switch on, 400 or 403, which the owner of the policy decision code decides;
  - the tenant-manager request that lists the tenants, and how the providers file names the Keycloak address of tenant
    realms.
