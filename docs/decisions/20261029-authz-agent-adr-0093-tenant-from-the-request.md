# Take the tenant of a decision from the request

## Status

Proposed

<!-- markdownlint-disable-next-line MD001 -->
#### Date

#### Owner

kichasov

#### Participants and approvers

The owner of the policy decision code, who decided on 2026-10-21 where the tenant of a decision comes from, confirmed
it on 2026-10-27, and decides the check of the user token. The owner of the policy decision code approves this record.
The project architect, who decided at two meetings on 2026-10-16 and in a questionnaire returned on 2026-10-19 that
Go computes the tenant. The Netcracker/qubership-authz-agent maintainers (kichasov). Assumption: the approvers'
GitHub accounts are added when this record is reviewed.

#### Related ADRs

- [authz-agent-ADR-0091: Verify tokens in Go against the keys of trusted providers](20261029-authz-agent-adr-0091-verify-tokens-in-go.md):
  the realms of tenants, which that record lists from tenant-manager.
- [authz-agent-ADR-0092: Accept only service tokens in Authorization on the check routes](20261029-authz-agent-adr-0092-service-tokens-in-authorization.md):
  the service token in `Authorization`, which is not checked against the tenant.

## Context

A check route receives a tenant from its caller in two places: the `tenant_id` query parameter and the `Tenant`
header. The calling service computes the tenant of its own request by a rule of its own and sends it in both. The
current policies do not read a tenant, and the architect decided that Go computes one and passes it to OPA with the
rest of the identity.

The parity cases of #42 for tenants take the tenant from `tenant_id` or from the `Tenant` header, also when the user
token names another tenant: `t3-query-names-other-tenant` and `t4-header-names-other-tenant` let a user of tenant B
ask about data of tenant A through a service with an M2M token.

Keycloak names a tenant's realm by a generated identifier and keeps the tenant's name only as the realm's display
name. tenant-manager returns the identifier of a tenant for its name.

## Decision

We will take the tenant of a decision from the request and pass it to OPA.

### The tenant of a decision

- The tenant is the non-empty `tenant_id`, else the non-empty `Tenant` header, else the default tenant. A token never
  sets it.
- The default tenant is a chart setting that holds a tenant's display name, `default` by default. Assumption: the
  setting is named `AUTHZ_DEFAULT_TENANT`. The agent resolves the name to the realm identifier through tenant-manager at
  start and serves no decision until it has.
- A non-empty tenant that the policy data does not know gets a deny.
- The service token is not checked against the tenant: a service with an M2M token may name any tenant.

### The check of the user token

The check decided so far compares the claim `tenant-id` of the user token in `Incoming-Token` with the tenant of the
request. A mismatch is logged as a warning that names both tenants, and with a switch on, off by default, the request
is refused before OPA. A user token without the claim is not compared.

The check runs only for a user token that passed verification, because it needs the provider of the token, and not
with `Authorization-Type: anonymous`, where the user token is ignored.

The owner of the policy decision code has proposed, and not yet decided, to compute the tenant of the user by the
rule the calling services use instead of reading the claim alone:

| User token | Tenant of the user |
| --- | --- |
| A token of `cloud-common` that is a cloud-level caller | The `Tenant` header; empty without it |
| A token of `external` | The claim `tenant-id`; empty without it |
| A token of any other provider | The realm of its provider: the identifier of a tenant realm, the provider id otherwise |

Under that proposal, a token of `cloud-common` is a cloud-level caller when it has the role `ROLE_CLOUD-ADMIN` or
`ROLE_M2M`, or a `level` of `m2m` or `key-manager` in any case, or a `level` of `external`. The refusal with the switch
on is proposed as a 400 with the reason code `INCOMING_TENANT_MISMATCH`.

### Justification

The calling service is the one that knows for which tenant it asks, and the parity cases of #42 take the tenant from
the request in the same way. A tenant computed from the token would answer those cases differently, and a user of one
tenant could no longer reach another tenant's data through a service that names it.

The default tenant gives every request a tenant, and a deployment names which one. Resolving it at start keeps a
misspelled or unknown default from denying every request of the default tenant without a word.

A verified token is worth more than a header, and a header only counts when a known service sends it. With an M2M
token in `Authorization` the service is known, so its tenant stands, and the user token is compared with it. The
proposed rule also covers a token of `external` without `tenant-id`, whose tenant is then empty. It treats a request
that names a tenant its own user token contradicts as invalid input rather than a denial, which is the reason for the
proposed 400 rather than 403.

Alternatives considered:

- **Compute the tenant of a decision from the token, by the rule the calling services use.** Rejected: the services
  already apply that rule and send its result, and the parity cases of #42 would get other answers.
- **Ignore `tenant_id`.** Rejected: a request that names its tenant only in `tenant_id` would go to the default
  tenant.

## Consequences

Positive:

- The tenant has one source, the request, and the policies receive it ready.
- A user token whose claim contradicts the tenant its service names shows up in the log, and can be refused.

Negative:

- A service with an M2M token can ask about any tenant. This is accepted: the architect holds that authorization data
  is not secret.
- A token of `external` without `tenant-id` reaches the tenant its service names, the default tenant included, while
  only the claim is compared.
- tenant-manager has to answer at start: until it does, the default tenant is unknown and the agent serves no
  decision.

Neutral:

- The chart renders the default tenant and the switch.
- Open points, decided as above until answered:
  - the check of the user token, the claim alone or the rule the calling services use, and the status of its refusal,
    400 or 403, which the owner of the policy decision code decides;
  - under the proposed rule, a field of the providers file that names the role of a provider, in place of the meaning
    the rule gives to the ids `cloud-common` and `external`;
  - under the proposed rule, a user of the chart's provider `default` gets the tenant `default` by the last row, while
    the default tenant resolves to a realm identifier, so every request of the default tenant would show a mismatch;
  - whether Go or a policy refuses a tenant that the policy data does not know, and how such a tenant differs from a
    known tenant whose policies are not loaded yet;
  - a deployment without tenant-manager, where the default tenant is used as given.
