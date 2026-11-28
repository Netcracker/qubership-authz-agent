# Let an operator override parts of the trusted providers through the Helm chart values

## Status

Proposed

<!-- markdownlint-disable-next-line MD001 -->
#### Owner

kichasov

#### Participants and approvers

- The project architect (`mr-joom`) approves this record, and with it the departures from earlier answers that it
  records. [A comment on #329](https://github.com/Netcracker/qubership-authz-agent/pull/329#issuecomment-7217023505)
  lists the departures of ADR-0104 with the meeting that agreed each; its item 9, the optional token for the API server
  agreed on 2026-11-23, is the departure that A10 of this record records. On 2026-11-23 the architect and the owner of
  the policy decision code also agreed to drop the M2M modes
  ([#345](https://github.com/Netcracker/qubership-authz-agent/pull/345)).
- The owner of the policy decision code (`vlsi`) reviews this record.
- The Netcracker/qubership-authz-agent maintainers (kichasov).

#### Related ADRs

- [authz-agent-ADR-0091: Verify tokens before policy evaluation against the keys of trusted issuers](20261029-authz-agent-adr-0091-verify-tokens-before-policy-evaluation.md):
  the Pod that stays not ready while keys do not arrive (ADR-0091 R19), a realm outside the readiness list that loads on
  its first token (ADR-0091 R16), and `IDENTITY_PROVIDER_URL`, which the agent does not read (ADR-0091 R78). This
  request deletes ADR-0091 R72, whose `IDENTITY_PROVIDER_URL` half is now R3 of this record and whose `caFile` half went
  with the member `caFile` (ADR-0104 R6), and ADR-0091 R13 (now R13 of this record). It adds three settings to those
  that ADR-0091 R64 removes: `AUTHZ_TRUSTED_PROVIDERS`, the list that A2 rejects; `AUTHZ_JWKS_HTTP_TIMEOUT`, which a
  time limit of the implementation replaces; and `AUTHZ_TRUSTED_PROVIDERS_FILE`, which ADR-0104 R1 leaves without a use.
  It drops from ADR-0091 R64 the `required` field of a provider, which ADR-0104 R6 refuses, gives ADR-0091 R65 a reason
  that holds for every setting of R64, states in the Negative consequences of ADR-0091 what replaces each setting that
  it adds, and names ADR-0094 R3, R26, R28, R31, and R32 in the entry of ADR-0091 for ADR-0094.
- [authz-agent-ADR-0092: Accept any verified token in Authorization and limit a caller that is not M2M to its tenant](20261029-authz-agent-adr-0092-tokens-in-authorization.md):
  ADR-0092 R15, under which `M2M_AUTH_MODE` changes no token that the agent accepts. This request makes ADR-0092 cite R2
  of this record where it cited ADR-0094 R30.
- [authz-agent-ADR-0094: Accept Kubernetes service account tokens from the namespaces of the installation](20261029-authz-agent-adr-0094-kubernetes-service-account-tokens.md):
  the term Token for the API server, the access to the keys of the API server (ADR-0094 Context), the check of the `aud`
  of a Kubernetes token (ADR-0094 R14), the token for the API server, which never goes to a PIP (ADR-0094 R28), and the
  Pod without the default token of its service account (ADR-0094 R31). This request deletes ADR-0094 R30 (now R2 of this
  record) and the token part of ADR-0094 R2 (now R6 of this record). It makes ADR-0094 cite R2 of this record where it
  cited R30 and R6 of this record where it cited R2, drops from its Participants the restatement of R2 of this record,
  and cites the Negative consequences of this record where it restated them.
- [authz-agent-ADR-0104: Describe the two trusted providers in a fixed directory of provider files](20261123-authz-agent-adr-0104-trusted-provider-files.md):
  the provider files that the chart writes, their format, and the keys that they may hold (ADR-0104 R6), the tokens
  whose `iss` matches no provider (ADR-0104 R19, R21), the reading of the provider files only at start (ADR-0104 R5),
  the agent without a realm of its own (ADR-0104 R13), the required sources (ADR-0104 R25), the errors that stop the
  start (ADR-0104 R18), the term In-cluster address and the addresses that the token for the API server may go to
  (ADR-0104 R24, R28), the warning on the issuer of the provider `kubernetes` (ADR-0104 R29), the host
  `kubernetes.default.svc` (ADR-0104 Context), and the http keys and the mode `ignore` of the provider
  `identity-provider`, the other identity provider under its key, and a provider `kubernetes` without
  `jwksBearerTokenFile` (the Justification and the Negative consequences of ADR-0104). This request makes ADR-0104 cite
  R13 of this record for the restart on upgrade, deletes the sentences of ADR-0104 that left the chart rules to this
  record, and drops the Follow-up of ADR-0104 that names this record.

## Context

ADR-0104 fixes the format of the provider files and the keys that they may hold, and leaves what they contain to
whoever deploys the agent. Before this record, the part of the chart was two rules each in ADR-0091 (R13, R72) and
ADR-0094 (R2, R30), and none of them said what an operator can override. This record decides what an operator can set
in the provider files through the values of the chart, and what the chart writes there by default.

The values of the chart in `helm-templates/authz-agent` are what an operator of an installation sets. Helm merges the
maps of several values files and of `--set` key by key, and replaces a list whole. The values carry
`IDENTITY_PROVIDER_URL`, the address of the platform's Keycloak without a realm, `http://identity-provider:8080` by
default, which serves each realm under the path `/auth/realms/` of that address. kubeadm gives the API server the issuer
`https://kubernetes.default.svc.<domain>`, built from the domain of the cluster, `cluster.local` by default
(`cmd/kubeadm/app/phases/controlplane/manifests.go`). The API server serves its keys only when its issuer is an https
URL (`pkg/serviceaccount/openidmetadata.go` and `pkg/controlplane` of Kubernetes).

## Decision

We will have the chart write the provider files of ADR-0104 from its values, with defaults derived from
`IDENTITY_PROVIDER_URL` and from the issuer that kubeadm gives with the default domain `cluster.local`, and let an
operator override an issuer, an address of keys, the token for the API server, or the realms that readiness waits for,
each without repeating the rest. An operator cannot leave a provider out or change the check of `aud`.

### Terms

- **Provider file**, **provider `identity-provider`**, **provider `kubernetes`**, **identity-provider token**,
  **Kubernetes token**, **in-cluster address**: as ADR-0104 defines them.
- **Token for the API server**: as ADR-0094 defines it.
- **Values**: the values of the chart in `helm-templates/authz-agent`: its `values.yaml` and what an installation sets
  over it.

### Rules

- **R2** (`chart`). The chart writes the provider `identity-provider` and the provider `kubernetes` in every
  installation, and no value leaves either of them out.
- **R17** (`chart`). The values change the provider files only as R3, R5, R6, and R16 allow.
- **R3** (`chart`). A Keycloak that serves each realm under the path `/auth/realms/` of `IDENTITY_PROVIDER_URL`, and
  names that address in the `iss` of its tokens, needs no value for the provider `identity-provider` but
  `IDENTITY_PROVIDER_URL`: the chart derives the issuers of its realms and the address of their keys from that address.
  The values can override the issuers, the address of the keys, or both, without repeating the rest of the provider,
  also when they come from several values files. The one that the values leave out is still derived from
  `IDENTITY_PROVIDER_URL`, not from the one they set. The provider trusts every realm of its Keycloak, and no value
  limits it to one realm.
- **R5** (`chart`). By default the provider `kubernetes` trusts the issuer
  `https://kubernetes.default.svc.cluster.local` and loads its keys from the API server at the host
  `kubernetes.default.svc`. The values can override the issuer, the address of the keys, or both, without repeating the
  rest of the provider, also when they come from several values files, and the one that the values leave out keeps its
  default. The chart writes an overridden address of the keys whether or not the Pod holds the token for the API server
  (R6), and leaves its check to the start of the agent (ADR-0104 R28).
- **R6** (`chart`). By default the chart gives the agent's Pod a token for the API server. The values can turn that
  token off, and the Pod then holds no token for the API server.
- **R13** (`chart`). An upgrade that changes a provider file restarts the agent's Pods, so a changed value takes effect
  without a manual restart.
- **R15** (`chart`). The chart writes the `audience` mode `ignore` for the provider `identity-provider` in every
  installation. ADR-0094 R14 decides the `aud` of a Kubernetes token.
- **R16** (`chart`). By default the list of realms whose keys a Pod waits for before it becomes ready holds only
  `cloud-common`. The values can replace that list with any list, one without `cloud-common` or an empty one included.

### Justification

The architect and the owner of the policy decision code chose to accept Kubernetes tokens wherever the chart deploys
the agent, so no value leaves the provider `kubernetes` out, and every installation verifies the tokens of the
platform's Keycloak, so none leaves the provider `identity-provider` out (R2). The values reach only the parts that an
installation has reason to change, so a value cannot add a member that the chart does not write (R17).

An operator changes one part of a provider, and repeating the parts that stay would copy defaults into every
installation that changes anything. So each value overrides one part, and the chart keeps the rest (R3, R5). Helm merges
the maps of several values files key by key (Context), so a part set in one file keeps the parts that another file sets.
Whether the values name these parts in a map keyed by the key of the provider or under names of their own is the chart's
choice. Deriving the provider `identity-provider` from `IDENTITY_PROVIDER_URL` means that an installation whose Keycloak
meets the condition of R3 sets no value for that provider but `IDENTITY_PROVIDER_URL`. A Keycloak whose tokens name a
public address in `iss` needs only the issuers, and its keys still load from the address that the chart derives, which
is why a part that the values leave out never follows the part that they set. The platform's Keycloak holds one realm
per tenant, so the provider trusts every realm of it (R3). The derived address of the keys is by default the http
address of `IDENTITY_PROVIDER_URL` inside the cluster, which ADR-0104 accepts for the provider `identity-provider` (the
Justification and the Negative consequences of ADR-0104).

The issuer of the API server differs between clusters. The default of R5 is the issuer that kubeadm gives with the
default domain of the cluster (Context). The default address of the keys names the host `kubernetes.default.svc`, which
a Pod resolves whatever the domain of the cluster is (ADR-0104 Context). An API server whose issuer is an https URL
serves its keys at an in-cluster address to any service account with a token for the API server (ADR-0094 Context), so
a managed cluster with another https issuer, or a kubeadm cluster with another domain, overrides only the issuer (R5).

The start of the agent refuses an address of the keys of the API server that is not an in-cluster address while the Pod
holds the token for the API server, and its error names the provider file and the member at fault (ADR-0104 R18, R28).
The chart leaves that check to the agent, so the check stays in one place, also for a deployment without the chart (R5).

A standard cluster refuses an anonymous request for its keys (ADR-0094 Context), and the agent's Pod holds no default
token of its service account (ADR-0094 R31), so by default the Pod holds a token for the API server. Turning it off is
for a cluster that serves its keys to an anonymous request: there no request needs the token, so the Pod does not hold
it (R6).

The chart writes for the provider `identity-provider` the mode `ignore` that ADR-0104 gives the platform's Keycloak (the
Justification of ADR-0104), and no value changes it (R15, R17). The `aud` of a Kubernetes token is not a value of the
chart: ADR-0094 R14 checks `netcracker` in every installation, whatever the provider files hold.

The agent reads the provider files only at start (ADR-0104 R5), so a changed value takes effect only in a new container.
Without a restart, an upgrade that changes a value would succeed while every Pod keeps the providers it started with
(R13).

The default is `cloud-common`, the platform's realm for M2M clients, so that a Pod becomes ready only once it can verify
the tokens of those clients. The agent holds no realm name of its own (ADR-0104 R13), so the chart supplies this default
(R16). An installation whose M2M clients use another realm, or that would rather become ready before any realm has
loaded keys, replaces the list (R16).

### Alternatives considered

- **A2. Let the values hold a whole list of providers, as `AUTHZ_TRUSTED_PROVIDERS` does, that replaces the providers
  the chart writes.** Rejected by R2 and R17: such a list could leave a provider out or set a member that no rule lets
  the values set. Rejected by R3 and R5 as well: an operator who changes one address would repeat every other part of
  both providers, and Helm replaces a list whole, so a second values file could not change one part of it (Context).
- **A18. Let the values replace the provider `identity-provider` or `kubernetes` with an object of their own.** Rejected
  by R3 and R5: an operator who changes one part would repeat the others, and a mistake in the copy shows only when the
  agent starts (ADR-0104 R6).
- **A3. Let the values set the check of `aud`.** Rejected by R15 and R17: the chart writes the mode that ADR-0104 gives
  the platform's Keycloak, and ADR-0094 R14 fixes the check of a Kubernetes token. A later stage that checks the `aud`
  of identity-provider tokens adds the value.
- **A4. Let the values limit the provider `identity-provider` to one realm.** Rejected by R3: the platform's Keycloak
  holds one realm per tenant, and such a provider would refuse the tokens of every other tenant.
- **A10. Give the Pod a token for the API server whatever the cluster allows.** Rejected by R6: on a cluster that serves
  its keys to an anonymous request, the Pod would hold a credential for the API server that no request needs. This
  reverses the token part of ADR-0094 R2, which mounted the token in every installation.
- **A11. Wait by default for the realms `cloud-common`, `default`, `cpq`, and `external`, the realms of
  `AUTHZ_IDP_REALMS`.** Rejected by R16: `default` is the display name of a tenant, not the name of a realm, most
  installations hold neither `cpq` nor `external`, and a name that the Keycloak does not hold keeps the Pod not ready.
- **A20. Keep `cloud-common` in the list of realms that readiness waits for, whatever the values say.** Rejected by R16:
  an installation whose M2M clients use another realm would wait for a realm that it does not need.
- **A12. Let a value leave the provider `kubernetes` out.** Rejected by R2: an installation that set it would refuse
  every token that the API server signs (ADR-0104 R21), where the architect and the owner of the policy decision code
  chose to accept Kubernetes tokens wherever the chart deploys the agent. The Negative consequences name what a cluster
  whose issuer is not an https URL pays for this.
- **A13. Write the provider `kubernetes` only in the M2M modes `hybrid` and `k8s`.** Rejected by R2: `M2M_AUTH_MODE`
  changes none of the tokens that the agent accepts (ADR-0092 R15), and without the provider the agent would refuse
  every token that the API server signs (ADR-0104 R21). This reverses the earlier answer that tied the provider to
  those modes.
- **A16. Offer no value for the issuer of the API server, and always trust the issuer that kubeadm gives.** Rejected by
  R5: a managed cluster often has another issuer, and so does a kubeadm cluster with another domain, and every token
  that its API server signs would get `TOKEN_ISSUER_UNKNOWN` (ADR-0104 R19, R21).
- **A19. Refuse at render an overridden address of the keys of the API server that is not an in-cluster address while
  the Pod holds the token for the API server.** Rejected by R5: the start of the agent refuses that address already
  (ADR-0104 R28), and the chart would hold a second copy of the rule.
- **A17. Leave the restart of the Pods after an upgrade to the operator.** Rejected by R13: an upgrade that changed a
  value would take no effect until someone restarted every Pod (Justification).

## Consequences

Positive:

- An installation whose Keycloak meets the condition of R3, and whose API server has the issuer that kubeadm gives with
  the default domain, sets no value of a provider but `IDENTITY_PROVIDER_URL` (R3, R5).
- A Keycloak at another host with the same paths, whose tokens name that host in `iss`, needs only a new
  `IDENTITY_PROVIDER_URL` (R3).

Negative:

- A Keycloak whose addresses differ from the ones that the chart derives, such as a Keycloak without `/auth` in its
  paths, needs both the issuers and the address of the keys in the values (R3).
- Through the chart an installation cannot trust one realm of its Keycloak alone or check the `aud` of identity-provider
  tokens. Each needs a change of the chart, or a deployment without the chart whose provider files are written by hand
  (R3, R15).
- The values can point the provider `identity-provider` at any server, and nothing tells that server from the platform's
  Keycloak; ADR-0104 names what that costs (R3).
- On a cluster whose API server has an https issuer other than the default of R5, as a managed cluster or a kubeadm
  cluster with another domain has, every token that the API server signs gets `TOKEN_ISSUER_UNKNOWN` in a ready Pod,
  until the values override the issuer (R5; ADR-0104 R19, R21). With the token for the API server, ADR-0104 R29 logs a
  warning at the start.
- Every Pod that the chart deploys waits for the keys of the provider `kubernetes` before it becomes ready (R2; ADR-0104
  R25). With the default address of R5, its readiness depends on the API server and on the agent's trust in the CA that
  signs the certificate of the API server (ADR-0094 Context). On a cluster whose API server has an issuer that is not an
  https URL, the API server serves no keys, so with the default address of R5 no Pod becomes ready, and the values
  cannot leave the provider `kubernetes` out (Context; R2; ADR-0091 R19).
- By default every Pod that the chart deploys holds a token for the API server, with the access of the agent's service
  account to the API server (R6). ADR-0104 R24 and R28 and ADR-0094 R28 limit where that token goes.
- An address of the keys of the API server that is not an in-cluster address renders, and then stops the start while
  the Pod holds a token for the API server (R5; ADR-0104 R28). Such an address works only with the token off, where its
  server serves the keys to an anonymous request (R6).
- With the token off, an installation pays the two costs that ADR-0104 names for a provider `kubernetes` without
  `jwksBearerTokenFile`: a Pod not ready on a cluster that refuses an anonymous request for its keys, and an issuer and
  an address of the keys that name another cluster, whose tokens then pass as Kubernetes tokens (R5, R6).
- A list of realms in the values replaces the default whole, so values that add a realm and still wait for
  `cloud-common` name it too. A list that leaves out the realm of the installation's M2M clients, an empty one included,
  makes a Pod ready before the keys of that realm have loaded, and the first token of such a client starts their load
  (R16; ADR-0091 R16).

Follow-ups:

- The documentation page of the chart values names the value for each override of R3, R5, R6, and R16, with its
  default and an example, such as the issuers and the address of the keys of a Keycloak without `/auth`. For each
  value it names the situation that calls for another value and what an operator observes when the value is wrong:
  the issuer of a managed cluster; the anonymous access to the keys that a Pod without the token needs; an address of
  the keys that is not an in-cluster address, which needs a Pod without the token; a list of realms, which replaces the
  default whole; and a cluster whose issuer is not an https URL, where no Pod becomes ready with the default address of
  the keys.
