# Accept Kubernetes service account tokens from the namespaces of the installation

## Status

Proposed

<!-- markdownlint-disable-next-line MD001 -->
#### Owner

kichasov

#### Participants and approvers

- The project architect (`mr-joom`) approves this record, and with it the answers it takes from the owner of the policy
  decision code on the keys, the checks, and the issuer.
- The owner of the policy decision code (`vlsi`) returned the questionnaire of 2026-11-03.
- The Netcracker/qubership-authz-agent maintainers (kichasov).

#### Related ADRs

- [authz-agent-ADR-0091: Verify tokens before policy evaluation against the keys of trusted issuers](20261029-authz-agent-adr-0091-verify-tokens-before-policy-evaluation.md):
  the trusted providers file, the reloads of the keys, the verifier in which the namespace check of this record runs,
  and the terms marked provider and Kubernetes token.
- [authz-agent-ADR-0092: Accept any verified token in Authorization and limit a caller that is not M2M to its tenant](20261029-authz-agent-adr-0092-tokens-in-authorization.md):
  ADR-0092 R11, the M2M modes, and ADR-0092 R7, a Kubernetes token as an M2M token.
- [authz-agent-ADR-0096: Choose the token the agent sends with a setting of its own](20261105-authz-agent-adr-0096-token-the-agent-sends.md):
  which token the agent sends, which this record does not decide.

## Context

Services of an installation call the agent with Kubernetes service account tokens as well as with realm tokens. The API
server of the cluster signs them, and the services request them with the audience `netcracker`, which every M2M call
between the services of an installation uses. Every Pod can also hold a token that the API server issues for its own
audience.

The API server names itself in the `iss` of every token it signs and publishes its keys under that address. In one
cloud that address cannot be reached from inside the cluster. A standard cluster grants discovery to the group
`system:serviceaccounts` through the ClusterRoleBinding `system:service-account-issuer-discovery`, so an anonymous
request gets 401 or 403 unless the cluster allows it. The keys are also at
`https://kubernetes.default.svc/openid/v1/jwks`, where any service account of the cluster may read them with a token
issued for the API server, and the server's certificate is signed by the cluster CA from the ConfigMap
`kube-root-ca.crt`. The agent's Pod sets `automountServiceAccountToken: false`.

ADR-0092 R11 defines the M2M modes of `M2M_AUTH_MODE` and which tokens each accepts.

The chart mounts projected tokens under `/var/run/secrets/tokens/<name>/token`, and a Pod can hold more than one.

One cluster hosts many installations, and the API server signs the tokens of all of them with the same keys. An
installation is a composite: a baseline and its satellites, each a blue-green domain with an origin and a peer
namespace. The platform creates the ConfigMap `topology` in every namespace, and its `data` key describes the composite
in a stable format.

## Decision

We will accept a Kubernetes token in the M2M modes `hybrid` and `k8s`, and only when a key of the API server of the
agent's own cluster verifies it, it passes the checks of this record, and its namespace belongs to the installation.

### Terms

- **Token for the API server**: the projected token at `/var/run/secrets/tokens/kubernetes/token`.
- **Cluster CA**: the CA at `/var/run/secrets/tokens/kubernetes/ca.crt`.
- **Token for `netcracker`**: the projected token at `/var/run/secrets/tokens/netcracker/token`, unless ADR-0096 R6
  names another file.
- **In-cluster address**: an address whose host is `kubernetes.default.svc` or `kubernetes.default.svc.cluster.local`.
- **Address outside the cluster**: an address with any other host.
- **Topology file**: `/etc/topology/data`, the `data` key of the ConfigMap `topology`.
- **Namespace of the installation**: the namespace the agent runs in, and the origin and the peer of the baseline and of
  every satellite in the topology file.

### Rules

#### The provider

- **R1** (`keys`). In the modes `hybrid` and `k8s` the trusted providers file holds exactly one marked provider. In
  `legacy` it holds none. Anything else stops the start.
- **R2** (`chart`). In the modes `hybrid` and `k8s` the chart mounts the token for the API server and the cluster CA.
- **R30** (`chart`). In the modes `hybrid` and `k8s` the chart writes the marked provider.
- **R31** (`chart`). The agent's Pod sets `automountServiceAccountToken: false`.
- **R3** (`chart`). The chart mounts the token for `netcracker` when ADR-0096 R2 chooses it.
- **R4** (`keys`). The `issuer` of the marked provider is the `iss` of the token for the API server. The agent reads it
  at start without checking its signature, because the kubelet wrote the file.
- **R5** (`keys`). A missing token for the API server stops the start in the modes `hybrid` and `k8s`.
- **R6** (`keys`). The keys are found through discovery under the issuer, unless the setting of R9 replaces the address.
- **R7** (`keys`). When the issuer is an https in-cluster address, the requests of discovery carry the token for the API
  server and trust the cluster CA, and so does the request to the `jwks_uri` that this address names.
- **R8** (`keys`). For any other issuer those requests carry no token.
- **R27** (`keys`). For any other issuer those requests trust the system roots together with, under
  `INTERNAL_TLS_ENABLED`, the CA in `CERTIFICATE_FILE_PATH`.
- **R9** (`chart`). A chart setting replaces the JWKS address and its CA, for a cluster whose issuer cannot be reached
  or does not publish a discovery document. The provider then reads the keys directly, and its `issuer` still comes from
  R4:

  ```json
  {"id": "kubernetes",
   "jwksUri": "https://kubernetes.default.svc/openid/v1/jwks",
   "caFile": "/var/run/secrets/tokens/kubernetes/ca.crt",
   "tokenFile": "/var/run/secrets/tokens/kubernetes/token",
   "audiences": ["netcracker"], "kubernetes": true}
  ```

- **R10** (`keys`). A marked provider with a `tokenFile` and a `jwksUri` outside the cluster stops the start.
- **R11** (`keys`). A marked provider lists `audiences` and does not set `allowMissingAud`, and anything else stops the
  start.
- **R12** (`keys`). The token for the API server goes only to the addresses of R7 and to the in-cluster `jwksUri` of R9.
- **R28** (`keys`). The token for the API server never goes to a PIP, because PIP addresses come from the policy
  configuration, and whoever controls one would get the agent's access to the API server.
- **R29** (`keys`). The token for the API server goes only over https, so a marked provider with a `tokenFile` and an
  http `jwksUri` stops the start.
- **R13** (`keys`). In every mode a provider that is not marked but has the id `kubernetes` or an in-cluster address in
  `issuer` or `jwksUri` stops the start, since its tokens would get no namespace check.
- **R26** (`chart`). A Pod holds up to two projected tokens: the token for the API server and the token for
  `netcracker`.

#### The checks

- **R14** (`verify`). The `aud` of a Kubernetes token contains `netcracker`. The codes are `TOKEN_AUDIENCE_MISSING` and
  `TOKEN_AUDIENCE_INVALID` of ADR-0091 R50.
- **R15** (`verify`). ADR-0091 R7, R46, and R48 apply to a Kubernetes token.
- **R16** (`verify`). The `sub` of a Kubernetes token starts with `system:serviceaccount:`, or the token gets
  `TOKEN_SUBJECT_INVALID`. Its parts are not parsed: the namespace comes from R18.

#### The namespaces

- **R17** (`namespaces`). A Kubernetes token is accepted only from a namespace of the installation.
- **R18** (`namespaces`). The namespace is the `namespace` member of the `kubernetes.io` claim. A token without it is
  refused.
- **R19** (`chart`). The chart mounts the ConfigMap `topology` with `optional: true`.
- **R20** (`namespaces`). While the topology file is missing, cannot be parsed, or names no composite, only the
  namespace the agent runs in is allowed.
- **R21** (`namespaces`). The agent reads the topology file again every 20 seconds.
- **R22** (`verify`). The check of R17 runs on a verified token taken from the cache too.
- **R23** (`namespaces`). A namespace that leaves the topology is refused once the kubelet has updated the mounted file
  and the next read has run, with no restart.
- **R24** (`verify`). A Kubernetes token is never accepted without the check of R17.
- **R25** (`namespaces`). A token that R17 or R18 refuses gets the code `TOKEN_NAMESPACE_NOT_ALLOWED`.

### Justification

The namespace check is what limits who gets in (R17). The audience keeps out the tokens that the API server issues for
other purposes, the default token of every Pod among them, but it does not limit who holds an accepted token: anyone who
can create a Pod can request a projected token for any audience, `netcracker` included. For the same reason a Kubernetes
token never passes without the namespace check (R24).

The signature cannot tell the services of one installation from those of another, because the API server signs both
with the same keys. The topology file is the platform's own description of the installation, kept in every namespace,
so the agent needs no list of its own.

Taking the issuer from the token for the API server needs no setting per cluster, and the token states exactly the value
the tokens of that cluster carry (R4). Discovery follows from the issuer in the same way, and the chart setting covers
the cluster where it does not work (R6, R9). A standard cluster opens discovery to service accounts only, so the request
to an in-cluster address carries the token for the API server (R7). Any other issuer gets no token, because the token
grants access to the API server of the cluster and to nothing else (R8). The API server serves TLS, and an ambient mesh
does not protect the path to it, because the mesh encrypts traffic only between its own Pods (R29).

A provider that looks like the API server and has no mark would accept the token of any Pod of the cluster with no
namespace check, in every mode, so it stops the start instead of warning (R13).

The mark decides which tokens are Kubernetes tokens, and neither the provider id nor the `kubernetes.io` claim does. The
id of this provider is a label the operator picks, and the claim is whatever the signer puts in the token, while the
mark follows the key that verified the token. The check of `sub` costs nothing, because the API server always sets that
prefix on a service account token (R16).

The agent calls the API server only to read its keys, not for every request, and needs no RBAC binding.

### Alternatives considered

- **A1. Ask the API server about every token with a TokenReview.** Rejected by R6: it adds a call to the API server for
  every new token and needs the `system:auth-delegator` role, while the JWKS is enough to verify a token locally.
- **A2. Accept every namespace while the topology file is missing.** Rejected by R20: a missing ConfigMap would open the
  agent to every installation of the cluster.
- **A3. Refuse to start without the topology file.** Rejected by R20: a namespace without the ConfigMap could not run
  the agent at all, not even for its own services.
- **A4. Always read the JWKS at a fixed address with the cluster CA.** Rejected by R6: the address would be a
  value to keep per cluster where discovery needs none, and the chart setting still covers the cluster that needs it.
- **A5. Set the issuer in the chart.** Rejected by R4: it differs per cluster, and the token for the API server already
  holds it.
- **A6. Send no token with discovery.** Rejected by R7: a standard cluster refuses such a request, so a Pod in `hybrid`
  or `k8s` would not become ready without the chart setting.
- **A7. Warn about a provider that looks like the API server and has no mark.** Rejected by R13: its tokens would pass
  with no namespace check, and a warning does not stop that.
- **A8. Run without Kubernetes tokens when the token for the API server is missing.** Rejected by R5: the readiness
  probe would pass while the agent refuses those tokens, and in `k8s` it would refuse every caller. A missing file is an
  error of the chart that no wait repairs, so the agent stops at the start.

## Consequences

Negative:

- Anyone who can create a Pod in a namespace of the installation can get a token the agent accepts.
- A service of the installation that receives a token for the audience `netcracker` can present it to the agent, since
  every M2M call between the services shares that audience.
- A token stays accepted until its `exp` after its Pod or service account is deleted, because the agent does not ask the
  API server. How long that is depends on the lifetime the caller requested.
- A namespace that joins the composite is accepted only after the kubelet updates the mounted file and the next read
  runs.
- In the default mode `legacy` every token that the API server signed is refused, so an installation whose services call
  the agent with such tokens has to run in `hybrid` or `k8s`.
- A missing token for the API server stops a Pod in `hybrid` or `k8s` at the start.
