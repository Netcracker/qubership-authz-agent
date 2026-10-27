# Accept Kubernetes service account tokens from the namespaces of the installation

## Status

Proposed

<!-- markdownlint-disable-next-line MD001 -->
#### Date

#### Owner

kichasov

#### Participants and approvers

The project architect, who settled the audience at a meeting on 2026-10-16 and the provider and the namespace list in
a questionnaire returned on 2026-10-27. The Netcracker/qubership-authz-agent maintainers (kichasov). Assumption: the
approvers' GitHub accounts are added when this record is reviewed.

#### Related ADRs

- [authz-agent-ADR-0084: Verify tokens in Go before OPA and pass the policies the verified identity](20261027-authz-agent-adr-0084-verify-tokens-in-go.md):
  the namespace check of this record runs in the Go verifier that record introduces, and a Kubernetes token counts as
  M2M there.
- [authz-agent-ADR-0085: Compute the tenant in Go from the verifying provider](20261027-authz-agent-adr-0085-tenant-from-the-verifying-provider.md):
  a Kubernetes token takes its tenant from the `Tenant` header.

## Context

Services of an installation call the agent with Kubernetes service account tokens as well as with Keycloak tokens. The
API server of the cluster signs them, and the services request them with the audience `netcracker`, which every M2M
call between the services of an installation uses. Every Pod can also hold a token that the API server issues for its
own audience.

The API server publishes its public keys at `https://kubernetes.default.svc/openid/v1/jwks`. Any service account of
the cluster may read that address with a token issued for the API server, and the server's certificate is signed by
the cluster CA from the ConfigMap `kube-root-ca.crt`. The agent's Pod sets `automountServiceAccountToken: false`. With
`KUBERNETES_M2M_ENABLED`, which is off by default, it mounts a token for the audience `netcracker` for its own calls.

The platform runs the services of an installation in one of three M2M modes, set in `M2M_AUTH_MODE`: `legacy` accepts
Keycloak M2M tokens only, `hybrid` accepts both kinds, and `k8s` accepts Kubernetes tokens only. `legacy` is the
default.

One cluster hosts many installations, and the API server signs the tokens of all of them with the same keys. An
installation is a composite: a baseline and its satellites, each a blue-green domain with an origin and a peer
namespace. The platform creates the ConfigMap `topology` in every namespace, and its `data` key describes the
composite in a stable format.

PR #159 marks a trusted provider of `internal/token/keys` as a Kubernetes API server with `kubernetes: true`, and
`internal/token/namespaces` reads the topology file. Neither is wired into the request path yet.

## Decision

We will accept a Kubernetes service account token in the M2M modes `hybrid` and `k8s`, and only when a key of the API
server of the agent's own cluster verifies it, it names the audience `netcracker`, and its namespace belongs to the
installation.

### The provider

- The trusted providers file lists the API server as one provider:

  ```json
  {"id": "kubernetes", "jwksUri": "https://kubernetes.default.svc/openid/v1/jwks",
   "caFile": "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
   "tokenFile": "/var/run/secrets/kubernetes.io/serviceaccount/token",
   "audiences": ["netcracker"], "kubernetes": true}
  ```

- Every token that a key of a provider marked `kubernetes` verifies is a Kubernetes token. Such a provider lists
  `audiences` and does not set `allowMissingAud`.
- The agent reads the JWKS at that address with the token and the CA of the file, and needs no RBAC binding.
- The chart mounts, at those two paths, a projected token issued for the API server and the CA bundle of the ConfigMap
  `kube-root-ca.crt`, since the Pod does not mount the default service account token.
- The chart takes `M2M_AUTH_MODE` with the values `legacy`, `hybrid`, and `k8s`, `legacy` by default, and lists the
  provider in the modes `hybrid` and `k8s`. In `legacy` a Kubernetes token is refused, as in the other services of the
  installation.

### The namespaces

- A Kubernetes token is accepted only from a namespace of the installation: the origin and the peer of the baseline and
  of every satellite in `/etc/topology/data`, the `data` key of the ConfigMap `topology`.
- The namespace is the `namespace` member of the `kubernetes.io` claim. A token without it is refused.
- The chart mounts the ConfigMap with `optional: true`. While the file is missing or cannot be parsed, only the
  namespace the agent runs in is allowed.
- The agent reads the file again every 20 seconds, and the check runs on a verified token taken from the cache too. A
  namespace that leaves the topology is refused once the kubelet has updated the mounted file and the next read has
  run, with no restart.
- A refused token gets the code `TOKEN_NAMESPACE_NOT_ALLOWED`.

### Justification

The audience limits the accepted tokens to those issued for the M2M calls of the platform. Without it, every token the
API server issues would be accepted, the default token of every Pod among them.

The signature cannot tell the services of one installation from those of another, because the API server signs both
with the same keys. The topology file is the platform's own description of the installation, kept in every namespace,
so the agent needs no list of its own.

The in-cluster address and the cluster CA are reachable from every Pod. The discovery document of the API server names
the JWKS under the issuer's address, which a Pod need not reach.

The mark decides which tokens are Kubernetes tokens, and neither the provider id nor the `kubernetes.io` claim does. The
id of this provider is a label the operator picks, and the claim is whatever the signer puts in the token, while the
mark follows the key that verified the token. The `sub` of the token is not checked separately: the audience and the
API server's key already admit only service account tokens.

Alternatives considered:

- **Ask the API server about every token with a TokenReview.** Rejected: it adds a call to the API server for every
  new token and needs the `system:auth-delegator` role, while the JWKS is enough to verify a token locally.
- **Accept every namespace while the topology file is missing.** Rejected: a missing ConfigMap would open the agent to
  every installation of the cluster.
- **Refuse to start without the topology file.** Rejected: a namespace without the ConfigMap could not run the agent at
  all, not even for its own services.
- **Find the JWKS through the API server's discovery document.** Rejected: the issuer's address it names need not be
  reachable from a Pod.

## Consequences

Positive:

- A token of another installation on the same cluster, a token issued for an audience other than `netcracker`, and a
  token of another cluster are refused.
- The agent calls the API server only to read its keys, not for every request, and needs no RBAC binding.

Negative:

- A service of the installation that receives a `netcracker` token can present it to the agent, since every M2M call
  between the services shares that audience.
- A token stays accepted until its `exp` after its Pod or service account is deleted, because the agent does not ask
  the API server. How long that is depends on the lifetime the caller requested.
- A namespace that joins the composite is accepted only after the kubelet updates the mounted file and the next read
  runs.
- In the default mode `legacy` every Kubernetes token is refused, so an installation whose services call the agent with
  Kubernetes tokens has to run in `hybrid` or `k8s`.

Neutral:

- The chart renders the provider and mounts the ConfigMap, the token, and the CA. Its values schema and the parser in
  `components/authz-agent/internal/authn` reject `kubernetes`, as they reject `caFile` and `tokenFile` of the new file;
  both change with the wiring of ADR-0084.
- The API server's keys are reloaded on the schedule that ADR-0084 sets for every provider.
- `M2M_AUTH_MODE` takes the place of `KUBERNETES_M2M_ENABLED`, which today chooses only the agent's own token. How the
  agent gets its own token in each mode is outside this record.
- Open point, decided as above until answered: what a topology file without `composite` allows. Today it allows no
  namespace, the agent's own included, so every Kubernetes token is refused in such a namespace; the architect has been
  asked whether such a file occurs.
