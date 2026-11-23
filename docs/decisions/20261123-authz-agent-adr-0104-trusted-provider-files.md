# Describe the two trusted providers in a fixed directory of provider files

## Status

Proposed

<!-- markdownlint-disable-next-line MD001 -->
#### Owner

kichasov

#### Participants and approvers

- The project architect (`mr-joom`) approves this record, and with it the departures from earlier answers that it
  records, agreed on 2026-11-19 and 2026-11-23.
- The owner of the policy decision code (`vlsi`) reviews this record.
- The Netcracker/qubership-authz-agent maintainers (kichasov).

#### Related ADRs

- [authz-agent-ADR-0091: Verify tokens before policy evaluation against the keys of trusted issuers](20261029-authz-agent-adr-0091-verify-tokens-before-policy-evaluation.md):
  this record replaces these statements of ADR-0091: the terms Trusted providers file, Provider, Marked provider,
  Realm, Source, Required source, Realm token, File token, Kubernetes token, and Issuer, and the words "discovery
  included" of the term Load; ADR-0091 R73, the shape of the file; ADR-0091 R1 and ADR-0091 R3 to R12, the issuers, the
  fields of a provider, the match of `iss`, and the address of the keys; ADR-0091 R15, the default `cloud-common`;
  ADR-0091 R49 and R50, the check of `aud`; and ADR-0091 R66, unknown fields. In every term and rule of ADR-0091 to
  ADR-0096 that stays, the provider files of this record together take the place of the trusted providers file, the
  provider `kubernetes` takes the place of the marked provider, the identity-provider token of R22 of this record
  takes the place of the realm token, and no token is a file token. Where such a term or rule names the checks of
  ADR-0091 or of ADR-0094, as ADR-0091 R60 and step 1 of ADR-0095 R1 do, those checks include R21, R26, and R27 of this
  record. In the rules of ADR-0091 on loading keys, a provider as a source of keys is an `exact` provider, and a realm
  in `keycloak.requiredRealms` is a realm that `readinessRealms` names, so the required sources in ADR-0091 R14, R16,
  R17, and R35 are those of R25 of this record. ADR-0091 R2 and R72 set and read the section `keycloak`, which R3
  of this record refuses; R3 takes precedence until a record of the chart and a record of a private CA replace them.
- [authz-agent-ADR-0092: Accept any verified token in Authorization and limit a caller that is not M2M to its tenant](20261029-authz-agent-adr-0092-tokens-in-authorization.md):
  ADR-0092 R6, R7, and R21, the M2M test of each kind of token, and ADR-0092 R11 to R14, the kinds of token that each
  M2M mode accepts. This record replaces ADR-0092 R8, which keeps a file token from being an M2M token. It limits
  ADR-0092 R12 to a token whose `iss` matches no provider (R21): a token that the API server signed and whose `iss`
  matches a provider other than `kubernetes` takes its keys from that provider (R23) and is refused under R27, or under
  ADR-0091 R44 when it comes from a Secret. This record also replaces the reason that ADR-0092 R16 gives for `legacy` as
  the only mode outside Kubernetes: a missing token for the API server stops the start in another mode.
  Pull request #265 moves R16 to the Consequences of ADR-0092.
- [authz-agent-ADR-0094: Accept Kubernetes service account tokens from the namespaces of the installation](20261029-authz-agent-adr-0094-kubernetes-service-account-tokens.md):
  this record replaces these statements of ADR-0094: the fixed path in the term Token for the API server, which becomes
  the file that `jwksBearerTokenFile` names, and the member `tokenFile` of ADR-0094 R10 and R29, which becomes
  `jwksBearerTokenFile`; ADR-0094 R4, the issuer from that token; ADR-0094 R5, the token that `hybrid` and `k8s`
  require, and the item of the ADR-0094 Consequences that says a missing token stops a Pod; ADR-0094 R6 to R8; the
  sentences of ADR-0094 R32 on discovery and on the setting of ADR-0094 R9; the item of the ADR-0094 Consequences that
  says an issuer that is not an https URL stops a Pod; the provider that the example of ADR-0094 R9 shows, in a format
  that R7 of this record refuses; ADR-0094 R11, the audiences of the provider; ADR-0094 R12, where that token goes,
  which R24 of this record takes over; ADR-0094 R13, a provider at the address of the API server; and ADR-0094 R14, the
  fixed audience `netcracker`. ADR-0094 R1 ties the provider `kubernetes` to the M2M modes, ADR-0094 R10 and R32 limit
  the address of its keys, and ADR-0094 R16 and R17 check its tokens.
- [authz-agent-ADR-0095: Refuse a check request before policy evaluation](20261029-authz-agent-adr-0095-refuse-before-policy-evaluation.md):
  ADR-0095 R16, the index of the reason codes, in which this record replaces the rules of `TOKEN_ISSUER_UNKNOWN`
  (ADR-0091 R5 and R11) with R21 of this record, and the rules of `TOKEN_AUDIENCE_MISSING` and `TOKEN_AUDIENCE_INVALID`
  (ADR-0091 R50 and ADR-0094 R14) with R26 of this record. R27 of this record adds the code
  `TOKEN_KUBERNETES_CLAIM_NOT_ALLOWED` to that index. ADR-0095 R3 and R18 decide the answer to a request whose
  `Incoming-Token` fails; #226 adds ADR-0095 R18.
- [authz-agent-ADR-0096: Choose the token the agent sends with a setting of its own](20261105-authz-agent-adr-0096-token-the-agent-sends.md):
  the agent's realm token of ADR-0096, the token that the agent obtains from the realm `cloud-common`, which is an
  identity-provider token under R22 of this record.

## Context

ADR-0091 verifies every token against the keys of trusted issuers before policy evaluation. Two servers sign the tokens
that an installation sends to the agent: the platform's Keycloak, with one realm per tenant, and the API server of the
cluster, which signs Kubernetes service account tokens (ADR-0094). Keycloak names a realm in `iss` as
`<address>/auth/realms/<realm>`, without `/auth` from Keycloak 17 on (the Keycloak 17 release notes), and serves the
keys of the realm at that address followed by `/protocol/openid-connect/certs`. ADR-0091 R73 describes the issuers in
one trusted providers file, with a `keycloak` section for the realms and a list of providers, one of which the member
`kubernetes: true` marks as the API server.

The API server puts the claim `kubernetes.io`, which holds the namespace and the service account, into every service
account token that the TokenRequest API issues, the token projected into a Pod among them
(`pkg/serviceaccount/claims.go` of Kubernetes). A token from a Secret of the type
`kubernetes.io/service-account-token` carries flat claims such as `kubernetes.io/serviceaccount/namespace` instead, and
no `exp` (`pkg/serviceaccount/legacy.go`).

A ConfigMap mounted as a directory without `subPath` shows each key as a symbolic link into a directory whose name
starts with `..`, and the kubelet updates the mount by switching that directory (`AtomicWriter` in
`pkg/volume/util/atomic_writer.go` of Kubernetes).

## Decision

We will read the trusted providers from the JSON files in the fixed directory `/etc/authz/providers`, accept only the
providers `identity-provider` and `kubernetes`, and let the `id` of a provider decide its checks. The `iss` of a token
will match the configured `issuer.value` as a whole, and the keys will come only from the configured `jwksUri`.

### Terms

- **Provider directory**: the directory that R1 names.
- **Provider file**: an entry of the provider directory that R2 makes one.
- **Provider**: an element of the `providers` array of a provider file.
- **Provider `identity-provider`**, **provider `kubernetes`**: the provider whose `id` is that value.
- **`exact` provider**, **`realm-template` provider**: a provider whose `issuer.type` is that value.
- **Realm**: a `realm-template` provider together with one realm name that R20 accepts.
- **Source**: an `exact` provider or a realm, as a place that keys are read from.
- **Required source**: a source that R25 names.
- **Issuer**: the value of the `iss` claim of a token.
- **Kubernetes token**, **identity-provider token**: the two kinds of token that R22 names.
- **In-cluster address**: as ADR-0094 defines it.
- **Stops the start**: as ADR-0091 defines it.

### Rules

#### The provider files

- **R1** (`keys`, `startup`). The agent reads its providers from the directory `/etc/authz/providers`. No setting
  changes this path.
- **R2** (`keys`). Every entry directly in the provider directory whose name ends in `.json` and does not start with `.`
  is a provider file, unless it is a directory or a symbolic link to one. The agent reads a provider file through a
  symbolic link, reads no directory, and skips every other entry of the provider directory.
- **R3** (`keys`). A provider file holds one JSON object whose only member is `providers`, an array. A provider file
  that the agent cannot read, or that holds anything else, stops the start.
- **R4** (`keys`). The providers of all provider files form one list. A provider directory that is missing or cannot
  be read, and a list without a provider, stop the start.
- **R5** (`startup`). The agent reads the provider directory and the provider files only at start.

#### The members of a provider

- **R6** (`keys`). The `id` of a provider is the string `identity-provider` or `kubernetes`. Any other `id` stops the
  start.
- **R7** (`keys`). A provider holds every member that this table marks as required for its `id`, may hold a member that
  it marks as optional, and holds no other member. A member with the value `null` breaks this rule. A provider that
  breaks this rule stops the start, so a provider that still holds one of the members `audiences`, `allowMissingAud`,
  `caFile`, `tokenFile`, `kubernetes`, or `required` stops it too:

  | Member | Provider `identity-provider` | Provider `kubernetes` |
  | --- | --- | --- |
  | `id` | Required | Required |
  | `issuer` | Required | Required |
  | `jwksUri` | Required | Required |
  | `jwksBearerTokenFile` | Not allowed | Optional |
  | `readinessRealms` | Optional in a `realm-template` provider, not allowed in an `exact` one | Not allowed |
  | `audience` | Required | Required |

- **R8** (`keys`). `issuer` is an object with the members `type` and `value` and no other. `type` is `exact` or
  `realm-template`, and the provider `kubernetes` takes only `exact`. `value` is a non-empty string. Any other
  `issuer`, a string among them, stops the start.
- **R9** (`keys`). In a `realm-template` provider, `issuer.value` and `jwksUri` are each an absolute URL that holds
  `{realm}` exactly once, as a whole segment of its path, so `{realm}` in the host or in part of a segment breaks this
  rule. In an `exact` provider, neither of them holds `{realm}`. A provider that breaks this rule stops the start.
- **R10** (`keys`). `jwksUri` is an absolute URL with the scheme `http` or `https`. Any other `jwksUri` stops the start.
  ADR-0094 R32 allows only `https` in the provider `kubernetes`.
- **R11** (`keys`). `audience` is either `{"mode": "matchAny", "values": [...]}`, where `values` is a non-empty array of
  non-empty strings, or `{"mode": "skipValidation"}`, which holds no `values`. The provider `kubernetes` takes only
  `matchAny`. Any other `audience` stops the start.
- **R12** (`keys`). `readinessRealms` is an array of strings. Each of them is a realm name as it stands in place of
  `{realm}` in `iss` after percent-decoding. The agent uses each name as written and resolves none of them through
  tenant-manager or another service. Any other `readinessRealms`, and a name that R20 does not accept, stop the start.
- **R13** (`keys`). A provider without `readinessRealms` names no realm as required, and the agent adds no realm of its
  own, `cloud-common` included.
- **R14** (`keys`). `jwksBearerTokenFile` is the absolute path of a file. Any other `jwksBearerTokenFile`, and one whose
  file the agent cannot read at start, stop the start.
- **R15** (`keys`). A provider `identity-provider` whose `issuer.value` or `jwksUri` is an in-cluster address stops the
  start.

#### The providers together

- **R16** (`keys`). Two providers with one `id`, in one provider file or in two, stop the start.
- **R17** (`keys`). Two providers that overlap stop the start. Two `exact` providers overlap when their `issuer.value`
  are equal. An `exact` and a `realm-template` provider overlap when the `issuer.value` of the `exact` one, taken as an
  `iss`, matches the `realm-template` one under R19. Two `realm-template` providers overlap when their `issuer.value`
  have the same scheme, host, and port and the same number of path segments, and are equal in each segment where
  neither holds `{realm}`.
- **R18** (`keys`). An error that stops the start under R3, R4, or R6 to R17 names the provider directory or the
  provider file at fault. An error under R3 names each member of the provider file other than `providers`, such as
  `keycloak`. Where the error concerns a provider, it names the provider by its `id`, or by its position in `providers`
  where the provider has no `id` that is a string, and it names the member at fault. An error under R16 or R17 names
  both providers, each with its provider file. An error about `jwksBearerTokenFile` in the provider
  `identity-provider` also says that the provider of Kubernetes tokens has the `id` `kubernetes`.

#### The source of a token

- **R19** (`keys`, `verify`). The `iss` of a token matches an `exact` provider when it equals `issuer.value` byte for
  byte, and that provider is then the source of the token. It matches a `realm-template` provider when it is longer
  than the bytes of `issuer.value` before and after `{realm}` together, starts with the bytes before `{realm}`, ends
  with the bytes after `{realm}`, and the bytes between those two parts percent-decode to a realm name that R20
  accepts; the realm with that name is then the source of the token. Nothing is normalized before the comparison: not
  the case of the scheme or the host, a default port, a trailing slash, or the percent-encoding outside the realm name.
- **R20** (`keys`). A realm name is accepted when it is valid UTF-8, is not empty, is not `.` or `..`, holds no `/`,
  `?`, `#`, or character of the Unicode class Cc, and is at most 255 bytes long.
- **R21** (`verify`). A token whose `iss` is missing or matches no provider under R19 is refused with
  `TOKEN_ISSUER_UNKNOWN`.
- **R22** (`verify`). A token whose source under R19 is the provider `kubernetes` is a Kubernetes token, and a token
  whose source is the provider `identity-provider` or one of its realms is an identity-provider token. The `id` of the
  provider alone decides the kind: no other member of the provider and no claim of the token changes it.

#### The keys

- **R23** (`keys`). The agent requests the keys of a source only at the `jwksUri` of its provider, as written. For a
  realm it puts the realm name, escaped as one path segment, in place of `{realm}`. It follows no redirect, requests no
  discovery document, and builds no address from a token other than by putting the realm name into `jwksUri`.
- **R24** (`keys`). The agent sends the token in the file that `jwksBearerTokenFile` names, as a bearer token, only with
  the requests for the keys of its provider. ADR-0094 R10 and R32 limit the addresses of those requests.
- **R25** (`keys`, `startup`). The required sources are every `exact` provider and every realm whose name the
  `readinessRealms` of its provider lists.

#### The audience

- **R26** (`verify`). A token whose provider has the `audience` mode `matchAny` passes the check of `aud` when its
  `aud` is a string that is one of the `values`, or an array of strings that holds one of them, compared byte for byte.
  A token without `aud` is refused with `TOKEN_AUDIENCE_MISSING`, and a token with any other `aud`, such as an array
  that also holds a number, is refused with `TOKEN_AUDIENCE_INVALID`. With the mode `skipValidation`, the agent does
  not check `aud`. The check is the same for a token in `Authorization` and in `Incoming-Token`.

#### Tokens of an API server

- **R27** (`verify`). A token that holds the claim `kubernetes.io`, whatever its value, and whose source under R19 is
  not the provider `kubernetes` is refused with `TOKEN_KUBERNETES_CLAIM_NOT_ALLOWED`.

### Implementation notes

Adds no requirement. Two files describe a Keycloak at `http://identity-provider:8080` and the API server of the
cluster. `identity-provider.json`:

```json
{
  "providers": [
    {
      "id": "identity-provider",
      "issuer": {"type": "realm-template", "value": "http://identity-provider:8080/auth/realms/{realm}"},
      "jwksUri": "http://identity-provider:8080/auth/realms/{realm}/protocol/openid-connect/certs",
      "readinessRealms": ["cloud-common"],
      "audience": {"mode": "skipValidation"}
    }
  ]
}
```

`kubernetes.json`:

```json
{
  "providers": [
    {
      "id": "kubernetes",
      "issuer": {"type": "exact", "value": "https://kubernetes.default.svc.cluster.local"},
      "jwksUri": "https://kubernetes.default.svc/openid/v1/jwks",
      "jwksBearerTokenFile": "/var/run/secrets/tokens/kubernetes/token",
      "audience": {"mode": "matchAny", "values": ["netcracker"]}
    }
  ]
}
```

A token with `iss` `http://identity-provider:8080/auth/realms/a%20b` selects the realm `a b`, whose keys the agent
requests at `http://identity-provider:8080/auth/realms/a%20b/protocol/openid-connect/certs`. In Go, `url.PathEscape`
escapes the name, and `os.Stat` on an entry follows a symbolic link.

### Justification

A fixed directory gives the agent one place to look and a deployment one place to mount, with no setting that the
chart and the agent have to agree on (R1). Several files let each provider stand in a file of its own (R2, R4). The
agent skips names that start with `.` and reads through symbolic links, because a ConfigMap mounted as a directory
keeps its data in hidden directories and links each key into them (R2). Reading the files only at start fixes the
providers of a process for its lifetime, and a change of the files restarts the Pods through the checksum of ADR-0091
R13 (R5).

A member that the agent ignored would be a setting that the operator relies on and the agent does not apply. Stopping
the start shows the mistake before any token is accepted, and a file in the former format cannot run with members that
the agent no longer reads, such as `allowMissingAud` or `caFile` (R3, R7 to R14).

The `id` decides the kind of a token, and with the kind the checks that other records attach to it: the namespace of
ADR-0094 R17, the M2M test of ADR-0092 R6, R7, and R21, and the future `iat` of ADR-0091 R48 (R6, R22). With two
values, a file cannot describe the API server under a third `id` that gets none of those checks. Further providers wait
for a later stage, which decides what their tokens may do.

A provider `identity-provider` whose issuer is the API server would accept the token of any Pod of the cluster with no
namespace check. Whatever address the provider files name, R27 refuses such a token by the claim `kubernetes.io`, which
every service account token from the TokenRequest API carries (Context). Where the provider names an in-cluster
address, which every cluster gives its API server, the provider stops the start under R15, so the mistake shows at the
start and not only in refusals. The claim never makes a token a Kubernetes token: R22 still decides the kind, and R27
only adds a refusal. In `legacy`, which has no provider `kubernetes`, every token from the TokenRequest
API is refused under R21 or R27, whatever the provider files hold. A token from a Secret has no `exp`, so ADR-0091 R44
refuses it.

`iss` names the signer, and RFC 7519, section 2, compares such values as case-sensitive strings with no
canonicalization. Comparing all of it, the host included, means a token that names another server starts no load, and
every verified token carries an `iss` in a form that the configuration names (R19). No `iss` can match two providers,
so a token has one source and no rule has to choose between providers (R17, R19). Only the provider
`identity-provider` can be a `realm-template` provider in this stage, so the overlap of two of them cannot occur yet;
R17 states it so that a later stage that allows another `id` keeps the same check.

A token selects its source but names no address: the keys come from the `jwksUri` that the operator wrote, so a token
cannot send the agent to a server of its choosing (R23). A configured `jwksUri` needs no discovery document, whose
server would choose the address of the keys, and it works where the issuer of the API server cannot be reached from
inside the cluster (ADR-0094 Context). `{realm}` stands for one whole path segment, and R20 keeps the decoded name from
adding a segment, a query, or a fragment, so the name stays inside its segment of the address (R9, R20, R23).

The agent holds nothing specific to Keycloak: the path `/auth/realms/`, the path of the keys, and the realm
`cloud-common` come from the provider files, so a Keycloak without `/auth` needs another file and no change of the agent
(R9, R13, R19, R23).

The required sources are the ones that the configuration names: an `exact` provider and the realms in
`readinessRealms` (R25). Every other realm loads on its first token. The names are the realm names that tokens carry,
because the agent runs where no tenant-manager exists (R12).

The token in `jwksBearerTokenFile` grants access to the API server, so only the provider `kubernetes` may name one, and
it goes only with the requests for the keys of that provider (R7, R24). A cluster that serves its keys to an anonymous
request needs no token, so the member is optional. A member that names a file the Pod does not hold is a fault of the
deployment that no wait repairs, so it stops the start (R14). An operator who sets `jwksBearerTokenFile` on the
provider `identity-provider` most likely meant the provider of Kubernetes tokens, so the error names its `id` (R18).

`audience` has no default, so the file states whether `aud` is checked. The platform's Keycloak has no audience mapper
that names the services of an installation, so a file for it sets `skipValidation`, which R11 allows. The check of a
provider is the same in both headers, so a Kubernetes token that the API server issued for another audience, such as
the default token of a Pod, passes in neither (R26).

### Alternatives considered

- **A1. Name the providers file with a setting, as `AUTHZ_TRUSTED_PROVIDERS_FILE` does.** Rejected by R1: every
  deployment mounts the files at one path, so the setting would only be one more value that the chart and the agent
  have to agree on.
- **A2. Mark the provider of the API server with `kubernetes: true` and accept any `id`.** Rejected by R6 and R22: the
  kind of a token would follow from a member that a file can set on any provider, and the `id` and the mark could
  disagree. This reverses ADR-0091 R6 and the choice of ADR-0094 that the mark, not the `id`, decides which tokens are
  Kubernetes tokens.
- **A3. Choose the checks of a provider with a member of its own, such as `type`, beside a free `id`.** Rejected by R6
  and R22: each kind of token has one provider in this stage, so a second member could only repeat the `id` or
  contradict it.
- **A4. Find the keys through OIDC discovery under the issuer.** Rejected by R23: the server of the discovery document,
  not the configuration, would choose the address of the keys, and in one cloud the issuer of the API server cannot be
  reached from inside the cluster. This reverses ADR-0091 R4 and its A8, which rejected a configured path of the keys,
  and ADR-0094 R6.
- **A5. Take the realm from the part of `iss` after the last slash, and leave the host uncompared.** Rejected by R19:
  a token that names any server would start a load at the configured Keycloak, and the `iss` of a verified token could
  name a server that the configuration does not. This reverses ADR-0091 R3 and the answer on the trusted realms in the
  questionnaire of 2026-11-03.
- **A6. Take the issuer of the provider `kubernetes` from the token for the API server.** Rejected by R7 and R8: the
  provider file states the issuer, and the token for the API server is optional, so the agent cannot rely on it to
  learn the issuer. This reverses ADR-0094 R4 and the answer on the issuer of the API server in the questionnaire of
  2026-11-03.
- **A7. Require the token for the API server in the modes `hybrid` and `k8s`.** Rejected by R7: a cluster that serves
  its keys to an anonymous request needs no token, and the Pod then holds no credential for the API server. This
  reverses ADR-0094 R5, and with it the reason that ADR-0092 gives for `legacy` as the only mode outside Kubernetes.
- **A8. Drop the provider `kubernetes` when the file that its `jwksBearerTokenFile` names is missing.** Rejected by
  R14: the readiness probe would pass while the agent refuses every Kubernetes token, and in `k8s` every caller.
- **A9. Give `readinessRealms` the default `cloud-common`.** Rejected by R13: the agent would carry the name of a realm
  of the platform's Keycloak, and a file for any other server would have to work around it. This reverses ADR-0091
  R15.
- **A10. Resolve the names in `readinessRealms` through tenant-manager, as for `AUTHZ_IDP_REALMS`.** Rejected by R12:
  the agent runs where no tenant-manager exists, and a token carries the realm name, not the display name of its
  tenant.
- **A11. Never check the `aud` of a Keycloak token, whatever the provider file states.** Rejected by R11 and R26: the
  provider file decides for each provider and in both headers, so a Keycloak that adds an audience for the services
  gets the check without a change of the agent. This reverses ADR-0091 R49 and departs from the answer on the `aud` of
  a Keycloak token in the questionnaire of 2026-11-03.
- **A12. Let one `iss` match two providers, and prefer one of them.** Rejected by R17: the source of a token would
  depend on a rule of precedence that an operator has to know. This reverses the precedence of a provider over the
  realm rule in ADR-0091 R7.
- **A13. Keep the tokens of an `exact` provider `identity-provider` from being M2M tokens, as ADR-0092 R8 does for a
  file token.** Rejected by R22: the `id` alone decides the kind, so both types of `issuer` of the provider
  `identity-provider` give an identity-provider token, and ADR-0092 R6 and R21 decide whether it is an M2M token. This
  reverses ADR-0092 R8.
- **A14. Accept a token with the claim `kubernetes.io` from the provider `identity-provider`, and state in the
  Consequences that a provider `identity-provider` whose issuer is an API server accepts the token of any Pod.**
  Rejected by R27: the safety of the agent would
  depend on the operator recognizing the API server under every address it has.
- **A15. Refuse a token under R27 with `TOKEN_KIND_NOT_ALLOWED` of ADR-0092 R13.** Rejected by R27: under R22 the token
  is an identity-provider token, which `Authorization` accepts in `legacy` and `hybrid`, and ADR-0095 keeps
  `TOKEN_KIND_NOT_ALLOWED` to show which services still call with such a token in `k8s`. A code of its own points at a
  provider file that names an API server.
- **A16. Give every provider a limit of its own on the tokens it accepts, such as the namespaces of the installation
  for the API server of the agent's cluster, in place of a kind of token.** Rejected by R22 and R27: no installation
  needs the tokens of another cluster in this stage, and such a limit would change ADR-0094 well beyond one rule. A
  later record can give each provider a limit and accept tokens that R27 refuses.

## Consequences

Positive:

- A Keycloak without `/auth`, or at another address, needs another provider file and no change of the agent (R9, R19,
  R23).

Negative:

- A file in the format of ADR-0091 stops the start (R3, R7, R8), so the agent, the chart, and the test stands move to
  the provider files in one change.
- An `iss` that differs from `issuer.value` in any byte, such as another case of the host, an explicit default port,
  or a trailing slash, gets `TOKEN_ISSUER_UNKNOWN` (R19, R21). A Keycloak whose tokens name it at another address
  than `issuer.value`, such as its public address, needs that address in `issuer.value`, and a Keycloak that issues
  tokens under two addresses cannot be described in this stage.
- After an upgrade to Keycloak 17 without `/auth`, new tokens get `TOKEN_ISSUER_UNKNOWN`, and the reloads of the realms
  that the agent holds fail, until the provider file names the new `issuer.value` and the new address of the keys (R19,
  R21, R23).
- A wrong `issuer.value` leaves the Pod ready: the keys of the provider still load from `jwksUri`, and every token of
  the provider gets `TOKEN_ISSUER_UNKNOWN` (R19, R21). For the provider `kubernetes` the issuer is a value set for each
  cluster, where ADR-0094 R4 read it from the token for the API server, so in `k8s` a wrong value refuses every
  caller of a Pod that is ready.
- A provider `identity-provider` without `readinessRealms` has no required source, so the Pod becomes ready before any
  realm has loaded keys, and a wrong `jwksUri` shows only in the refusals of its tokens and in the warnings of
  ADR-0091 R81 (R13, R25; ADR-0091 R23, R38, R39, R81).
- Outside Kubernetes the agent starts in `hybrid` or `k8s` when the provider files hold a provider `kubernetes`
  without `jwksBearerTokenFile` (R7, R14). Only `legacy` is supported there, and the agent does not check it.
- A provider `kubernetes` without `jwksBearerTokenFile` requests its keys without a token. A standard cluster refuses
  that request (ADR-0094 Context), and the Pod stays not ready (ADR-0091 R19).
- A name in `readinessRealms` that the Keycloak does not hold, such as the display name of a tenant, keeps the Pod not
  ready until the file changes (R12; ADR-0091 R14, R19).
- A change of a provider file takes effect only at the next start (R5).
- A token of an `exact` provider `identity-provider` is an identity-provider token (R22), so the M2M test of ADR-0092 R6
  and R21 applies to it, where ADR-0092 R8 kept the tokens of a provider outside the realms of the Keycloak from being
  M2M tokens.
- No rule of this record names the CA that the requests of R23 trust. ADR-0091 R2 and R72, the member `caFile` of
  ADR-0091 R6, and ADR-0094 R7 and R27 named one for the requests that this record replaces, and a `caFile` now stops
  the start under R3 or R7 of this record. An https `jwksUri` whose certificate a private CA or the cluster CA signs
  therefore works only once the agent trusts that CA in another way.
- R15 recognizes the API server only by the hosts of an in-cluster address. A provider `identity-provider` whose
  `issuer.value` equals the issuer of an API server and whose `issuer.value` and `jwksUri` are not in-cluster
  addresses, as with the public issuer and keys of a managed cluster, passes R15. Where no provider `kubernetes` has the
  same `issuer.value` (R17), as in `legacy` or for the API server of another cluster, the agent starts. R27 then
  refuses every token whose source is that provider and that holds the claim `kubernetes.io`, and the mistake shows
  only in those refusals.
- A token that a signer other than an API server issues and that holds the claim `kubernetes.io`, such as a Keycloak
  token with a mapper that adds it, is refused (R27).
- A provider `kubernetes` without `jwksBearerTokenFile` may name the issuer and the keys of the API server of another
  cluster, because ADR-0094 R10 limits the address of its keys only when that member is set (R7, R24). The tokens of
  that cluster are then Kubernetes tokens, which R27 does not refuse, and ADR-0094 R17 compares only the names of their
  namespaces, which another cluster can also use.
- An `Incoming-Token` with an `aud` that its provider does not accept fails the check of R26, and the request gets the
  denial of every resource of ADR-0095 R18 rather than a decision without that token.

Follow-ups:

- ADR-0091, ADR-0092, ADR-0094, ADR-0095, and ADR-0096 drop the statements that this record replaces and use its
  terms. ADR-0091 R19 cites R14 of this record in place of ADR-0094 R5, ADR-0091 R29 cites R19 to R21 of this record
  in place of ADR-0091 R5, ADR-0091 R54 names the kinds of R22 of this record, and ADR-0091 R64 adds
  `AUTHZ_TRUSTED_PROVIDERS_FILE` to the settings that go away. Every Justification sentence, alternative, consequence,
  and Related ADRs line of ADR-0091 to ADR-0096 that cites a statement this record replaces, or names realm tokens and
  file tokens, is rewritten, among them ADR-0091 A2 and A8, ADR-0094 A1 and A4 to A9, the Justification and A5 of
  ADR-0095, and the terms and the Justification of ADR-0096. The Justification of ADR-0094 adds that R27 of this
  record uses the claim `kubernetes.io` only to refuse a token. The item of the ADR-0094 Consequences on `legacy` cites
  R27 of this record. ADR-0092 R12 applies only to a token whose `iss` matches no provider. ADR-0095 R16 lists
  `TOKEN_KUBERNETES_CLAIM_NOT_ALLOWED` with R27 of this record.
- ADR-0092, and ADR-0101, which #235 proposes, state that only `legacy` is supported outside Kubernetes and that the
  agent does not check it.
- ADR-0091 R2 and R72 and ADR-0094 R9 set or read members of the trusted providers file that R3 and R7 of this record
  remove, ADR-0094 R2 and R30 decide what the chart mounts and writes for the provider `kubernetes`, and ADR-0094 R7
  and R27 and the term Cluster CA name the CA of requests that this record replaces. A record of the chart and a record
  of a private CA take their place.
- `docs/decisions/README.md` names the provider files in the row of the layer `keys`, and this record as the one that
  defines the words for providers, realms, sources, issuers, and the two kinds of token.
- The Compose example of ADR-0101, which #235 proposes, mounts the provider directory at `/etc/authz/providers`.
