# Take the tenant of a decision from the verified user token, then from the request

## Status

Proposed

<!-- markdownlint-disable-next-line MD001 -->
#### Owner

kichasov

#### Participants and approvers

- The owner of the policy decision code (`vlsi`) approves this record.
- The project architect (`mr-joom`) decided that Go computes the tenant, and where it comes from.
- The Netcracker/qubership-authz-agent maintainers (kichasov).

#### Related ADRs

- [authz-agent-ADR-0091: Verify tokens before policy evaluation against the keys of trusted issuers](20261029-authz-agent-adr-0091-verify-tokens-before-policy-evaluation.md):
  the verification that makes the claim `tenant-id` usable, and ADR-0091 R14, the readiness conditions.
- [authz-agent-ADR-0092: Accept any verified token in Authorization and limit a caller that is not M2M to its tenant](20261029-authz-agent-adr-0092-tokens-in-authorization.md):
  ADR-0092 R4 and R5 compare a caller that is not M2M with the tenant of this record.
- [authz-agent-ADR-0095: Refuse a check request before policy evaluation](20261029-authz-agent-adr-0095-refuse-before-policy-evaluation.md):
  ADR-0095 R1, the order of the steps before policy evaluation.
- [authz-agent-ADR-0096: Choose the token the agent sends with a setting of its own](20261105-authz-agent-adr-0096-token-the-agent-sends.md):
  the agent's token, which the call to tenant-manager carries.

## Context

A check route receives a tenant from its caller in two places: the `tenant_id` query parameter and the `Tenant` header.
A user token can carry the claim `tenant-id` as well, and not every user token has it. The current policies do not read
a tenant, and the architect decided that Go computes one and passes it to policy evaluation.

The name of a realm is the identifier of its tenant, but the key under which the policy data of a tenant is stored need
not equal that name: on the test stand the default tenant is stored under `default`, in the realm `parity`.

## Decision

We will take the tenant of a decision from the verified user token, then from the request, and pass it to policy
evaluation.

### Terms

- **Tenant of the decision**: the tenant that R1 selects for a request.
- **Default tenant**: the tenant that R10 to R14 name.
- **Policy source**: the service that the agent pulls policy snapshots from.
- **Key of the policy data**: the key under which the policy data of a tenant is stored.

### Rules

#### The tenant of a decision

- **R1** (`handler`). The tenant of the decision is the first of:
  1. the non-empty claim `tenant-id` of an `Incoming-Token` that passed verification and is not an M2M token;
  2. the non-empty `tenant_id`;
  3. the non-empty `Tenant` header;
  4. the default tenant.
- **R2** (`handler`). A token that failed verification and an M2M token do not set the tenant, and the token in
  `Authorization` never does.
- **R3** (`handler`). An `Incoming-Token` that ADR-0091 R38 refuses ends the request with the 503 of ADR-0095 R3, so an
  outage does not move the tenant of a decision.
- **R4** (`handler`). The claim, `tenant_id`, and `Tenant` are compared as keys of the policy data, byte for byte.
- **R5** (`handler`). A value from the request is compared with the default tenant that R11 or R14 gives, never with the
  name in `AUTHZ_DEFAULT_TENANT` before its translation.
- **R6** (`handler`). The agent passes the tenant of the decision to policy evaluation.
- **R7** (`client`). Calls to PIPs, entitlements, and User Management send the tenant of the decision in the `Tenant`
  header.

#### A tenant that the request contradicts

- **R8** (`handler`). A `tenant_id` or a `Tenant` header that differs from the claim is logged as a warning that names
  both tenants.
- **R9** (`handler`). The mismatch does not refuse the request, and the decision is computed in the tenant of the claim.
  ADR-0092 R4 still applies to a caller that is not M2M.

#### The default tenant

- **R10** (`startup`). The name comes from `AUTHZ_DEFAULT_TENANT`, `default` without it.
- **R11** (`startup`). With an address in `AUTHZ_TENANT_MANAGER_URL`, the agent translates the name through
  tenant-manager at start, with the agent's token of ADR-0096, and is not ready until it has.
- **R12** (`startup`). A warning for each attempt and a metric show why the agent waits for that translation.
- **R13** (`startup`). The translation has to give the key of the policy data of that tenant.
- **R14** (`startup`). With an empty address the name is used as given, in Kubernetes and outside it. An installation
  whose tenant-manager returns a value other than the key of the policy data leaves the address empty and sets
  `AUTHZ_DEFAULT_TENANT` to that key.
- **R15** (`startup`). A default tenant that is not among the tenants of the policy data gets a warning and a metric at
  start.

#### A tenant without data

- **R16** (`handler`). A tenant the policy data does not know gets 200 and a deny from Go, and empty lists on a bulk
  route.
- **R17** (`startup`). The list of tenants comes from the policy source, and the agent is ready once every tenant of
  that list has an accepted snapshot. A snapshot that never arrives keeps it not ready.
- **R18** (`handler`). A tenant whose snapshot the agent rejected at its first pull after the start is not served: its
  requests get a deny.
- **R19** (`startup`). The agent stays not ready until it accepts a snapshot of that tenant.
- **R20** (`startup`). A warning and a metric tell that tenant from a tenant the policy data does not know.
- **R21** (`startup`). After the agent became ready, a rejected snapshot leaves the last accepted one of that tenant in
  place, and the agent stays ready.

### Justification

A verified token is worth more than a header, and the calling service already knows which user it acts for. Taking the
tenant from the claim keeps a service from asking in the name of a user about a tenant that the user's own token
contradicts (R1). A token without the claim leaves the request as the only source, so the tenant still has a value. An
M2M token does not set the tenant, because a service forwards its own token under `Authorization-Type: anonymous`, and
an M2M token may name any tenant (R2).

A warning rather than a refusal keeps calling services working while their mismatches come to light: a refusal would
fail requests that succeed today (R8, R9).

The default tenant gives every request a tenant, and a deployment names which one. Translating it at start keeps a
misspelled default from denying every request of that tenant without a word (R11). Deciding by the address gives one
rule for every deployment, and a namespace or a kind cluster without tenant-manager needs only an empty address (R14).

Sending the tenant of the decision on outgoing calls keeps a PIP from answering for another tenant than the policies
evaluate (R7).

Most production installations have one or two tenants, so a rejected snapshot often belongs to the tenant that carries
the traffic. An agent that stayed ready would replace the working Pods in a rollout and deny that tenant while its
readiness probe passes. An agent that stays not ready stops the rollout, and the old Pods go on serving (R19).

### Alternatives considered

- **A1. Take the tenant only from the request.** Rejected by R1: a verified claim would lose to a header.
- **A2. Refuse a request whose tenant differs from the claim.** Rejected by R9: it fails calling services in production.
- **A3. Derive the tenant of a user from the realm of the token.** Rejected by R1: the realm need not be the key of the
  policy data, as the test stand shows.
- **A4. Read the default tenant from a configuration service.** Rejected by R10: an environment variable is enough, and
  it works without one.
- **A5. Deny a tenant with a rejected snapshot and stay ready.** Rejected by R19: a rollout would replace the working
  Pods, and the readiness probe would pass while that tenant gets a deny on every request.
- **A6. Stay not ready only for a rejected snapshot of the default tenant.** Rejected by R19: where another tenant
  carries the traffic, its rejected snapshot would have the same effect.

## Consequences

Negative:

- A request that names another tenant than the `tenant-id` of the user's token is evaluated by the policies of the
  user's tenant, so it can be allowed where the current answer is a deny, whichever is the subject. The golden
  `tenant-claim/tc7-claim-in-the-end-user-token` shows it: `false` today, `true` here.
- A user token without `tenant-id` reaches the tenant its service names, the default tenant included, when that service
  is M2M. ADR-0092 R4 limits a service that is not.
- A deployment with tenant-manager needs it at start: until it answers, the agent is not ready.
- A translation that returns a value other than the key of the policy data leaves the default tenant without data, and
  its requests get a deny.
- The chart's default address is `http://tenant-manager:8080`, so a namespace without tenant-manager has to set the
  address empty, or the agent never becomes ready.
- Tokens must be verified before the tenant is known, which sets the order of the steps in ADR-0095 R1.
- A rejected snapshot of one tenant keeps every new Pod from becoming ready. A snapshot rejected at the first pull keeps
  the agent not ready, so the trigger is any restart after a bad policy was published, such as a node drain, an
  eviction, or an OOM kill. After a restart of all Pods, every tenant of the installation waits for that snapshot to be
  fixed. A single agent on a VM or a deployment with one replica has no old Pods to go on serving, so there every
  restart does this.
