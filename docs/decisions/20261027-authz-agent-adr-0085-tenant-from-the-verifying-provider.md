# Compute the tenant in Go from the verifying provider

## Status

Proposed

<!-- markdownlint-disable-next-line MD001 -->
#### Date

#### Owner

kichasov

#### Participants and approvers

The project architect, who decided at two meetings on 2026-10-16 and in a questionnaire returned on 2026-10-19 that Go
computes the tenant and that a tenant realm is found through tenant-manager. The owner of the policy decision code,
who chose on 2026-10-27 to keep the current tenant rule and to take the realm from the verifying provider. The
Netcracker/qubership-authz-agent maintainers (kichasov). Assumption: the approvers' GitHub accounts are added when this
record is reviewed.

#### Related ADRs

- [authz-agent-ADR-0084: Verify tokens in Go before OPA and pass the policies the verified identity](20261027-authz-agent-adr-0084-verify-tokens-in-go.md):
  the tenant is one of the fields that record passes to OPA.
- [authz-agent-ADR-0086: Accept Kubernetes service account tokens from the namespaces of the installation](20261027-authz-agent-adr-0086-kubernetes-service-account-tokens.md):
  which tokens are Kubernetes tokens.

## Context

The current policies do not read a tenant. The architect decided that Go computes one and passes it to OPA with the
rest of the identity.

Keycloak names a tenant's realm by a generated identifier and keeps the tenant's name only as the realm's display
name, so a chart cannot name that realm. tenant-manager maps a tenant's name to the identifier:
`GET /api/v4/tenant-manager/registration/tenants?dns=<name>` returns it as a plain-text body. The test stand runs an
emulator of that request, and the emulator is not published.

The agent does not check `iss`: the `kid` of a token selects the key, and the key belongs to one provider of the
trusted providers file. The chart composes the provider of each platform realm from the realm's name and uses the name
as the provider id. Its default realms are `cloud-common`, `default`, `cpq`, and `external`.

A caller may send a tenant in the `Tenant` header and in the `tenant_id` query parameter of a check route. The agent
ignores `tenant_id` today.

## Decision

We will compute the tenant in Go, from the provider whose key verified the token, and pass it to OPA.

### Tenant realms

- A provider that sets `tenantRealm: true` names the tenant in the last path segment of its `issuer`, and the
  top-level `tenantManagerUrl` names tenant-manager. At start the agent asks tenant-manager for the realm identifier of
  each such tenant, retrying until it gets an acceptable answer, and uses the identifier in place of the name for the
  life of the process.
- Assumption: of the chart's default realms, `default` is a tenant realm, and `cloud-common`, `cpq`, and `external`
  are not.

### The rule

The realm of a token is the realm of the provider whose key verified it: the identifier tenant-manager gave for a
tenant realm, and the provider id for any other provider.

| Subject | Tenant |
| --- | --- |
| The anonymous user | The `Tenant` header |
| A Kubernetes token | The `Tenant` header |
| A cloud-level caller of `cloud-common` | The `Tenant` header; empty without it |
| A token of `external` | The claim `tenant-id`; empty without it |
| Any other token | The realm of its provider |

- A token of `cloud-common` is a cloud-level caller when it has the role `ROLE_CLOUD-ADMIN` or `ROLE_M2M`, or a `level`
  of `m2m` or `key-manager` in any case, or of `external`.
- For any other token the `Tenant` header is ignored, also when it names another tenant.
- Where the rule takes the `Tenant` header and the request has none, the `tenant_id` query parameter takes its place.
  For any other token `tenant_id` is ignored.
- An empty tenant becomes the default tenant, a new chart setting whose default value is `default`. Assumption: the
  setting is named `AUTHZ_DEFAULT_TENANT`.
- The agent refuses to start when the trusted providers file lists no provider `cloud-common`, so a misspelled id of
  the platform realm is found at start.

### Justification

The verifying provider is the only source of the realm that the agent has checked. `iss` is not checked, so it cannot
decide the tenant.

The provider ids `cloud-common` and `external` are the names of platform realms that the chart writes itself, not
labels an operator picks. A Kubernetes provider has no realm, so ADR-0086 marks it instead.

A user of a tenant realm cannot reach another tenant: the realm comes from the key, and neither the header nor the
query parameter overrides it. The header and the query parameter count only for the callers whose tenant the token does
not carry: the anonymous user, a Kubernetes token, and the cloud-level callers of `cloud-common`. Both come from the
calling service, which the agent has already verified by its M2M token.

The default tenant gives every request a tenant, and a deployment names which one.

Alternatives considered:

- **Take the realm from `iss`.** Rejected: `iss` is not checked.
- **Mark the platform realms in the providers file, as ADR-0086 marks the Kubernetes provider.** Rejected: the chart
  writes these ids itself, and the check at start catches a misspelled `cloud-common`.
- **Let the `Tenant` header override the realm of a tenant realm token.** Rejected: a user of one tenant would choose
  another.
- **Let a non-empty `tenant_id` override the rule.** Rejected: the calling service would choose the tenant of a tenant
  realm user.
- **Leave an empty tenant empty.** Rejected in this proposal: every policy would have to decide what an empty tenant
  means.

## Consequences

Positive:

- The tenant is computed once, from what the agent verified, and the policies receive it ready.

Negative:

- Every tenant realm needs tenant-manager at start: until it answers for each tenant, the agent does not start.
- A tenant realm added after the start is not known until the Pods restart.
- Any caller with an M2M token chooses the tenant of the anonymous user, of a Kubernetes token, and of a cloud-level
  caller, through the `Tenant` header or `tenant_id`.
- A misspelled `external` is not caught at start: its tokens take the realm of their provider instead of `tenant-id`.

Neutral:

- `internal/token/keys` exposes the resolved realm of a provider, which it keeps internal today.
- The chart renders `tenantRealm`, `tenantManagerUrl`, and the default tenant, and `AUTHZ_TENANT_MANAGER_URL` becomes
  `tenantManagerUrl`. The documentation page of the trusted providers file, which the wiring change adds, describes
  them.
- An installation outside the cloud needs a published tenant-manager emulator.
- Open points, decided as above until the owner of the policy decision code answers:
  - whether an empty tenant becomes the default tenant;
  - which roles and `level` values make a token of `cloud-common` a cloud-level caller;
  - whether `tenant_id` replaces a missing `Tenant` header.
