# Describe the two trusted providers in a fixed directory of provider files

## Status

Proposed

<!-- markdownlint-disable-next-line MD001 -->
#### Owner

kichasov

#### Participants and approvers

- The project architect (`mr-joom`) approves this record, and with it the departures from earlier answers that it
  records. [A comment on #329](https://github.com/Netcracker/qubership-authz-agent/pull/329#issuecomment-7217023505)
  lists each departure with the meeting that agreed it, and asks the architect to confirm the two changes made after the
  review of 2026-11-27 that touch what the architect agreed, A21 and A22. The comments on
  [#263](https://github.com/Netcracker/qubership-authz-agent/issues/263#issuecomment-7168247169),
  [#301](https://github.com/Netcracker/qubership-authz-agent/issues/301#issuecomment-7167555755), and
  [#305](https://github.com/Netcracker/qubership-authz-agent/issues/305#issuecomment-7167551957) record the decisions of
  2026-11-25. The architect and the owner of the policy decision code dropped the M2M modes on 2026-11-23
  ([#345](https://github.com/Netcracker/qubership-authz-agent/pull/345)), so no rule of this record depends on
  `M2M_AUTH_MODE`.
- The owner of the policy decision code (`vlsi`) reviews this record, and on 2026-11-24 proposed the format of a
  provider file that R6 states.
- The Netcracker/qubership-authz-agent maintainers (kichasov).

#### Related ADRs

- [authz-agent-ADR-0091: Verify tokens before policy evaluation against the keys of trusted issuers](20261029-authz-agent-adr-0091-verify-tokens-before-policy-evaluation.md):
  the term Stops the start, the readiness that waits for a usable key of every required source (ADR-0091 R14, R19), the
  loads and the codes of a token whose key is not found (ADR-0091 R23, R38, R39, R81), the checks of a token (ADR-0091
  R40 to R48), and what a line of the application log may name (ADR-0091 R75). This request deletes from ADR-0091 the
  rules whose place this record takes: R73, R6, and R66 (now R6 of this record), R1 and R3 (now R19 of this record), R4
  and R9 (now R23 of this record), R5 (now R20 and R21 of this record), R7 (now R17 and R19 of this record), R8 (now R6
  of this record), R10 (now R24 and R28 of this record), R11 (now R21 of this record), R12 (now R5 of this record), R15
  (now R13 of this record), R49 (now R26 of this record), and R50 (now R26 of this record, and ADR-0094 R14 for a
  Kubernetes token). It also deletes ADR-0091 R2 with the member `caFile`. It deletes the terms Trusted providers file,
  Marked provider, File token, and Realm token, points the other terms for providers and tokens at this record, drops
  discovery from the term Load, and restates ADR-0091 R14, R16, R17, R19, R21, R29, R34, R35, R37, R48, R52, R54, R60,
  R75, A2, A8, and A15 in the terms of this record.
- [authz-agent-ADR-0092: Accept any verified token in Authorization and limit a caller that is not M2M to its tenant](20261029-authz-agent-adr-0092-tokens-in-authorization.md):
  the M2M test of an identity-provider token (ADR-0092 R6, R21) and of a Kubernetes token (ADR-0092 R7), the kinds of
  token that `Authorization` accepts (ADR-0092 R11), and ADR-0092 R15, under which `M2M_AUTH_MODE` changes no token
  that this record accepts. This request points the terms of ADR-0092 for tokens at this record, makes ADR-0092 R6, R11,
  R21, and A4 name the kinds of R22, and deletes ADR-0092 R8, which A13 reverses.
- [authz-agent-ADR-0094: Accept Kubernetes service account tokens from the namespaces of the installation](20261029-authz-agent-adr-0094-kubernetes-service-account-tokens.md):
  the checks of a Kubernetes token (ADR-0094 R14, R16 to R18, R25), the https rule for the keys of the provider
  `kubernetes` (ADR-0094 R32), and the projected tokens that the chart mounts (ADR-0094 R26). This request deletes from
  ADR-0094 the rules whose place this record takes: R1 (now R16 of this record), R4 and R5 (reversed by A6 and A7 of
  this record, with R6 and R14 of this record in their place), R6, R8, and the token half of R7 (now R23 and R24 of this
  record), the address half of R9 (now R6 and R23 of this record), R10 and R12 (now R24 and R28 of this record), R11
  (now R6 of this record), and R29 (now R6 of this record). It deletes ADR-0094 R13, which stopped the start for a
  provider that looked like the API server, with no successor (A19), and ADR-0094 R27 and the CA halves of ADR-0094 R7
  and R9, which named the CA of the requests that this record replaces, with no successor here. It also deletes ADR-0094
  A4 to A6, which rejected a fixed address of the keys, an issuer set in the configuration, and discovery without a
  token: this record configures the address and the issuer and drops discovery (R6, R23). It deletes ADR-0094 A7, which
  rejected a warning in place of R13. It deletes the term In-cluster address, which this record now defines, and the
  term Address outside the cluster. It makes the token for the API server the token in the `jwksBearerTokenFile` of the
  provider `kubernetes`, points the terms of ADR-0094 for providers and tokens at this record, and restates ADR-0094
  R14, R18, R28, R32, A1, A8, and A9 in the terms of this record.
- [authz-agent-ADR-0095: Refuse a check request before policy evaluation](20261029-authz-agent-adr-0095-refuse-before-policy-evaluation.md):
  the steps of a check request (ADR-0095 R1), the answer to a request whose `Incoming-Token` fails a check (ADR-0095
  R3), the limit on audit records (ADR-0095 R12), the line that a refusal writes in the application log (ADR-0095 R14),
  and the index of reason codes (ADR-0095 R16). This request makes steps 1 and 2 of ADR-0095 R1 name the checks of this
  record, and makes ADR-0095 R16 index `TOKEN_ISSUER_UNKNOWN` by R21, and `TOKEN_AUDIENCE_MISSING` and
  `TOKEN_AUDIENCE_INVALID` by R26 and ADR-0094 R14.
- [authz-agent-ADR-0096: Choose the token the agent sends with a setting of its own](20261105-authz-agent-adr-0096-token-the-agent-sends.md):
  the token that the agent obtains from the realm `cloud-common`, which is an identity-provider token under R22. This
  request makes ADR-0096 call that token an identity-provider token, and cite R14 of this record where it cited
  ADR-0094 R5.
- [authz-agent-ADR-0105: Let an operator override parts of the trusted providers through the Helm chart values](20261123-authz-agent-adr-0105-providers-through-chart-values.md):
  the provider files that the chart writes from its values (ADR-0105 R2, R3, R5, R16, R17), the token for the API server
  that the chart gives the Pod (ADR-0105 R6), and the restart of the Pods when an upgrade changes a provider file
  (ADR-0105 R13).

## Context

ADR-0091 verifies every token against the keys of trusted issuers before policy evaluation. Two servers sign the tokens
that an installation sends to the agent: the platform's Keycloak, with one realm per tenant, and the API server of the
cluster, which signs Kubernetes service account tokens (ADR-0094). Keycloak names a realm in `iss` as
`<address>/auth/realms/<realm>`, without `/auth` from Keycloak 17 on (the Keycloak 17 release notes), and serves the
keys of the realm at that address followed by `/protocol/openid-connect/certs`. Before this record, ADR-0091 described
both servers in one trusted providers file, with a `keycloak` section for the realms and a list of providers, one of
which the member `kubernetes: true` marked as the API server. The platform passes the address of its Keycloak to the
services of an installation in `IDENTITY_PROVIDER_URL`, an address inside the cluster: an http one by default, such as
`http://identity-provider:8080`, and an https one with internal TLS, such as `https://identity-provider:8443`.

A service account token that the TokenRequest API issues, the token projected into a Pod among them, names the issuer of
the API server in `iss` (`GenerateToken` in `pkg/serviceaccount/jwt.go` of Kubernetes). A token from a Secret of the
type `kubernetes.io/service-account-token` names `kubernetes/serviceaccount` in `iss` and has no `exp` (`LegacyIssuer`
in `pkg/serviceaccount/legacy.go`). A projected token expires, and the kubelet writes a new one into the file before it
does.

The API server is reachable inside the cluster as `kubernetes.default.svc` and as `kubernetes.default.svc.<domain>`. A
Pod resolves the first name through the search domains in its `/etc/resolv.conf`, whatever the DNS domain of the
cluster. kubeadm uses the second name as the issuer of the API server
(`cmd/kubeadm/app/phases/controlplane/manifests.go`).

A ConfigMap mounted as a directory without `subPath` shows each key as a symbolic link into a directory whose name
starts with `..`, and the kubelet updates the mount by switching that directory (`AtomicWriter` in
`pkg/volume/util/atomic_writer.go` of Kubernetes).

## Decision

We will read the trusted providers from the JSON files in the fixed directory `/etc/authz/providers`, accept only the
providers under the keys `identity-provider` and `kubernetes`, and let the key of a provider decide its checks. The
`iss` of a token will match the configured `issuer` or `issuerTemplate` as a whole, and the keys will come only from
the configured `jwksUri`.

### Terms

- **Provider directory**: the directory that R1 names.
- **Provider file**: an entry of the provider directory that R2 makes one.
- **Provider**: a member of the `providers` object of a provider file, named by its key.
- **Provider `identity-provider`**, **provider `kubernetes`**: the provider under that key.
- **`realms` provider**, **`single` provider**: a provider whose `type` is that value.
- **Realm**: a `realms` provider together with one realm name that R20 accepts.
- **Source**: a `single` provider or a realm, as a place that keys are read from.
- **Required source**: a source that R25 names.
- **Issuer**: the value of the `iss` claim of a token.
- **Kubernetes token**, **identity-provider token**: the two kinds of token that R22 names.
- **In-cluster address**: an address whose host is `kubernetes.default.svc` or `kubernetes.default.svc.cluster.local`.
- **Stops the start**: as ADR-0091 defines it.

### Rules

#### The provider files

- **R1** (`keys`, `startup`). The agent reads its providers from the directory `/etc/authz/providers`. No setting
  changes this path.
- **R2** (`keys`). Every entry directly in the provider directory whose name does not start with `.` is a provider file
  when its name ends in `.json` and it is a regular file or a symbolic link that resolves to one. The agent reads a
  provider file through a symbolic link and skips every entry whose name starts with `.`. Any other entry of the
  provider directory, such as a file whose name ends in `.yaml` or a directory, stops the start.
- **R3** (`keys`). A provider file stops the start when the agent cannot read it, when its content is not a JSON text
  under RFC 8259, or when one of its objects holds two members with the same name.
- **R4** (`keys`). The providers of all provider files form one set. A provider directory that is missing or cannot be
  read stops the start, and so does a set without a provider.
- **R5** (`startup`). The agent reads the provider directory and the provider files only at start.

#### The format of a provider file

- **R6** (`keys`). A provider file is valid under the JSON Schema
  [`api/provider-file.v1.schema.json`](../../api/provider-file.v1.schema.json), draft 2020-12. A provider file that the
  schema does not accept stops the start.

#### The members of a provider

- **R12** (`keys`). Each name in `readinessRealms` is a realm name as it stands in place of `{realm}` in `iss` after
  percent-decoding. The agent uses each name as written and resolves none of them through tenant-manager or another
  service. A name that R20 does not accept stops the start.
- **R13** (`keys`). A provider without `readinessRealms` names no realm as required, and the agent adds no realm of its
  own, `cloud-common` included.
- **R14** (`keys`). A `jwksBearerTokenFile` whose file the agent cannot read at start stops the start.

#### The providers together

- **R16** (`keys`). Two provider files that each hold a provider under the same key stop the start.
- **R17** (`keys`). Two providers that overlap stop the start. Two `single` providers overlap when their `issuer` values
  are equal. A `single` and a `realms` provider overlap when the `issuer` of the `single` one, taken as an `iss`,
  matches the `realms` one under R19.
- **R18** (`keys`). Every error with which this record stops the start names the provider directory, the entry, or the
  provider file at fault, the member at fault where there is one, and the key of the provider where the fault lies in
  a provider. An error under R6 names the schema by its `$id`. For a key or a member that the schema does not accept in
  its place, the error names the keys or members that it accepts there; for a value outside a list of values, it names
  that list; and for any other value that the schema refuses, it names the type, the length, or the pattern that the
  value does not meet. An error about a member that only the other provider accepts also names the key of that
  provider. An error under R4 for a missing provider directory says that no setting changes its path. An error under
  R16 or R17 names both providers, each with its provider file.

#### The source of a token

- **R19** (`keys`, `verify`). The `iss` of a token matches a `single` provider when it equals `issuer` byte for byte,
  and that provider is then the source of the token. It matches a `realms` provider when it is longer than the bytes of
  `issuerTemplate` before and after `{realm}` together, starts with the bytes before `{realm}`, ends with the bytes
  after `{realm}`, and the bytes between those two parts percent-decode to a realm name that R20 accepts; the realm with
  that name is then the source of the token. Nothing is normalized before the comparison: not the case of the scheme or
  the host, a default port, a trailing slash, or the percent-encoding outside the realm name.
- **R20** (`keys`). A realm name is accepted when it is valid UTF-8, is not empty, is not `.` or `..`, holds no `/`,
  `?`, `#`, or character of the Unicode class Cc, and is at most 255 bytes long.
- **R21** (`verify`). A token whose `iss` is missing or matches no provider under R19 is refused with
  `TOKEN_ISSUER_UNKNOWN`.
- **R30** (`handler`). The line that a refusal with `TOKEN_ISSUER_UNKNOWN` writes in the application log (ADR-0095 R14)
  names the `iss` of the token, in quotes as text taken from the token and cut to its first 200 bytes, or says that the
  token holds no `iss`. An `Incoming-Token` that fails with `TOKEN_ISSUER_UNKNOWN` writes such a line too, rate-limited
  per client address and reason code as ADR-0095 R12 limits audit records.
- **R22** (`verify`). A token whose source under R19 is the provider `kubernetes` is a Kubernetes token, and a token
  whose source is the provider `identity-provider` or one of its realms is an identity-provider token. The key of the
  provider alone decides the kind: no other member of the provider, its `type` included, and no claim of the token
  changes it. A check that a record attaches to a Kubernetes token never runs on an identity-provider token, and an
  identity-provider token that holds the claim `kubernetes.io` gets no check and no refusal from that claim.

#### The keys

- **R23** (`keys`). The agent requests the keys of a source only at the `jwksUri` of its provider, as written. For a
  realm it puts the realm name, escaped as one path segment, in place of `{realm}`. It follows no redirect, requests no
  discovery document, and builds no address from a token other than by putting the realm name into `jwksUri`.
- **R24** (`keys`). The agent sends the token in the file that `jwksBearerTokenFile` names, as a bearer token, only with
  the requests for the keys of its provider, and reads the file again for each of those requests. A load for which the
  agent cannot read the file sends no request and ends in a failure (ADR-0091 R39). R28 and ADR-0094 R32 limit the
  addresses of those requests.
- **R28** (`keys`). A provider `kubernetes` whose `jwksBearerTokenFile` is set and whose `jwksUri` is not an in-cluster
  address stops the start.
- **R29** (`keys`, `startup`). At start, once the agent has read the file that the `jwksBearerTokenFile` of the provider
  `kubernetes` names (R14), it reads the `iss` of the token in it without checking its signature, and logs at most one
  warning:
  1. when the token holds no `iss` that the agent can read, a warning that says so;
  2. when the `iss` is `kubernetes/serviceaccount`, a warning that the file holds a token from a Secret rather than a
     projected token, and the agent compares nothing;
  3. otherwise, when the `iss` differs byte for byte from the `issuer` of the provider, a warning that names both
     values and says to set `issuer` to the `iss` of the token.

  Each warning names the provider file and the file that `jwksBearerTokenFile` names, and never holds the token. The
  warning changes neither the start nor readiness. Without `jwksBearerTokenFile` the agent compares nothing.
- **R25** (`keys`, `startup`). The required sources are every `single` provider and every realm whose name the
  `readinessRealms` of its provider lists.

#### The audience

- **R26** (`verify`). An identity-provider token whose provider has the `audience` mode `matchAny` passes the check of
  `aud` when its `aud` is a string that is one of the `values`, or an array of strings that holds one of them, compared
  byte for byte. Such a token without `aud` is refused with `TOKEN_AUDIENCE_MISSING`, and one with any other `aud`, such
  as an array that also holds a number, is refused with `TOKEN_AUDIENCE_INVALID`. With the mode `ignore`, the agent
  does not check `aud`, whether the token has one or not. ADR-0094 R14 checks the `aud` of a Kubernetes token.

### Implementation notes

Adds no requirement. The files in [`api/examples/provider-file/valid`](../../api/examples/provider-file/valid) describe
a Keycloak at `http://identity-provider:8080` with a realm for each tenant, an identity provider with one issuer and a
checked `aud`, and the API server of the cluster. Each names the schema in `$schema`, which the schema allows, so an
editor that reads JSON Schema validates and completes the file. The schema refuses each file in
[`api/examples/provider-file/invalid`](../../api/examples/provider-file/invalid), for the reason that its name gives. A
test of the agent can read both directories and check that the checks of R6 accept every file under `valid` and refuse
every file under `invalid`.

A token with `iss` `http://identity-provider:8080/auth/realms/a%20b` selects the realm `a b`, whose keys the agent
requests at `http://identity-provider:8080/auth/realms/a%20b/protocol/openid-connect/certs`. In Go, `url.PathEscape`
escapes the name, and `os.Stat` on an entry follows a symbolic link.

A JSON Schema validator for draft 2020-12 can check a file against `api/provider-file.v1.schema.json`. The patterns of
the schema use only syntax that ECMA-262 and Go's `regexp` read alike. ECMA-262 is the dialect that draft 2020-12 names
for `pattern`.

### Justification

A fixed directory gives the agent one place to look and a deployment one place to mount, with no setting that a
deployment and the agent have to agree on (R1). Several files let each provider stand in a file of its own (R2, R4). The
agent skips names that start with `.` and reads through symbolic links, because a ConfigMap mounted as a directory
keeps its data in hidden directories and links each key into them (R2). Reading the files only at start fixes the
providers of a process for its lifetime, so a deployment that changes a provider file restarts the agent to apply it
(R5; ADR-0105 R13).

A JSON Schema states the format of a provider file in one place, in a notation that validators and editors read, and
the other rules state what the agent does with each member (R6). The schema is a file of its own with an `$id`, so a
provider file can name it in `$schema`, an editor then validates and completes the file without setup, and the version
in the name of the file gives the format a version for later changes. R20 stays outside the schema, because R19
applies it to the realm name in an `iss` as well, and its limit counts bytes, where `maxLength` of JSON Schema counts
characters (R12, R20).

`providers` is an object keyed by the name of each provider. A misspelled key gets one error that names it, where a
misspelled name inside a list of providers gets an error from every branch of the schema, and an editor offers exactly
the two keys. R3 already refuses one key twice in one file, so R16 compares only the files. `type` decides which members
a provider accepts, so a missing or unknown `type` gets one error, and an editor offers the members of the chosen type.
Its values `realms` and `single` name the shape of a provider, one issuer per realm or one issuer, rather than how `iss`
is compared, because R19 compares `iss` byte for byte for both.

The format is built to take more identity providers later without a new format. This stage trusts two providers: the
platform's Keycloak and the API server of the cluster. Later stages may add an identity provider of a project, aliases
of one issuer (`issuerAliases`), a check of the `aud` of an identity-provider token that differs between the two
headers, and provider files that a project mounts beside those of the deployment. The provider file is shaped for that.
`providers` is an object keyed by name, so a new provider is a new key, and the files written for this stage stay valid.
`type` says how a provider names its issuers, apart from its key. `audience` is an object that can gain a mode, and a
later provider that needs an audience of its own can carry one. The agent merges every provider file of the directory,
so another file can add a provider (R2, R4). The schema file carries its version in its name,
`provider-file.v1.schema.json`, which its `$id` repeats, so a later format gets a file and an `$id` of its own. Each new
key needs a record of its own that decides what its tokens may do: their kind and the checks they get. Until such a
record exists, R6 refuses any other key (R6, R22).

A member that the agent ignored would be a setting that the operator relies on and the agent does not apply. Stopping
the start shows the mistake before any token is accepted, and a file in the former format cannot run with members that
the agent no longer reads, such as `allowMissingAud` or `caFile` (R3, R6). An entry of the provider directory that the
agent skipped would drop a provider in the same way: with the file of the provider `kubernetes` named `kubernetes.yaml`,
the Pod would report ready and refuse every Kubernetes token. So an entry that is not a provider file stops the start
too, and the error names it (R2, R18). An error that names the accepted keys and values, the schema, and the fixed path
tells the operator what to write, where an error that names only the fault leaves that to a search (R18).

The key decides the kind of a token, and with the kind the checks that other records attach to it, such as the
namespace check of ADR-0094 R17, the M2M test of ADR-0092 R6, R7, and R21, and the future `iat` of ADR-0091 R48 (R6,
R22). With two keys, a file cannot describe the API server under a third key that gets none of those checks. Further
providers wait for a later stage, which decides what their tokens may do. The key `identity-provider` keeps the name
that the platform's `IDENTITY_PROVIDER_URL` gives its Keycloak. No check can tell that Keycloak from another identity
provider that a file describes under the same key, and the tokens of such a provider pass the M2M test of ADR-0092 R6
and R21 with whatever claims it signs. Whoever writes the provider files answers for what stands under that key, and the
Negative consequences accept that cost (R22).

The claim `kubernetes.io` is whatever the signer puts in a token, so it decides neither the kind of a token nor which
checks run on it (R22). A provider `identity-provider` whose `issuer` names an API server therefore makes the tokens of
that API server identity-provider tokens, with no namespace check. The architect accepted that cost on 2026-11-25, and
the Negative consequences name it (R22). Where the provider files hold no provider `kubernetes`, as outside Kubernetes,
a token that an API server signed is refused under R21, unless a provider `identity-provider` names its issuer (R22).
A token from a Secret has no `exp` (Context), so ADR-0091 R44 refuses it.

`iss` names the signer, and RFC 7519, section 2, compares such values as case-sensitive strings with no
canonicalization. Comparing all of it, the host included, means a token that names another server starts no load, and
every verified token carries an `iss` in a form that the configuration names (R19). No `iss` can match two providers, so
a token has one source and no rule has to choose between providers (R17, R19). A wrong `issuerTemplate`, or a wrong
`issuer` that R29 does not catch, shows only in refusals with `TOKEN_ISSUER_UNKNOWN`, and the `iss` in the log line of
such a refusal shows which byte differs, where the reason code alone does not (R30). An unverified `iss` is text that
the sender of the token chose, so the line quotes it and cuts it, and a stream of `Incoming-Token` values with invented
issuers writes no more lines than the limit allows (R30; ADR-0091 R75).

A token selects its source but names no address: the keys come from the `jwksUri` that the operator wrote, so a token
cannot send the agent to a server of its choosing (R23). A configured `jwksUri` needs no discovery document, whose
server would choose the address of the keys, and it works where the address in the `iss` of the API server cannot be
reached from inside the cluster (ADR-0094 Context). `{realm}` stands for one whole path segment, and R20 keeps the
decoded name from adding a segment, a query, or a fragment, so the name stays inside its segment of the address (R6,
R20, R23).

The keys of a provider decide which tokens of that provider pass, so a host on the path to `jwksUri` that answered with
keys of its own could sign tokens that pass. The keys of the provider `kubernetes` come only over https (ADR-0094 R32).
The schema accepts http for the keys of the provider `identity-provider`, because by default `IDENTITY_PROVIDER_URL`
gives the platform's Keycloak an http address inside the cluster (Context), and the Negative consequences accept that
its keys are then protected only by the network of the cluster (R6).

The agent holds nothing specific to Keycloak: the path `/auth/realms/`, the path of the keys, and the realm
`cloud-common` come from the provider files, so a Keycloak without `/auth` needs another file and no change of the agent
(R6, R13, R19, R23).

The required sources are the ones that the configuration names: a `single` provider and the realms in
`readinessRealms` (R25). Every other realm loads on its first token. The names are the realm names that tokens carry,
because the agent runs where no tenant-manager exists (R12).

The token in `jwksBearerTokenFile` grants access to the API server of the cluster, so only the provider `kubernetes` may
name one, and it goes only with the requests for the keys of that provider (R6, R24). The kubelet replaces a projected
token before it expires (Context), so the agent reads the file for each request rather than keeping the token that it
read at start (R24). A host outside the cluster that received the token would get that access, so R28 keeps the token
to an in-cluster address. The architect decided on 2026-11-25 to keep the two host names of an in-cluster address for
R28 rather than learn the DNS domain of the cluster
([#301](https://github.com/Netcracker/qubership-authz-agent/issues/301#issuecomment-7167555755)), and
`kubernetes.default.svc` reaches the API server whatever that domain is (Context). A cluster that serves its keys to an
anonymous request needs no token, so the member is optional. A member that names a file the Pod does not hold is a
fault of the deployment that no wait repairs, so it stops the start (R14). An operator who sets `jwksBearerTokenFile` on
the provider `identity-provider` most likely meant the provider of Kubernetes tokens, so the error names its key (R18).

The issuer of the provider `kubernetes` is a value of the provider file (R6; A6). A wrong value leaves the Pod ready
while every token that the API server signs gets `TOKEN_ISSUER_UNKNOWN` (R21). The token in `jwksBearerTokenFile` comes
from the API server of the cluster, so its `iss` shows the issuer that the provider should name, and a warning at the
start points at the mistake before the refusals do. The comparison only warns: the agent reads the token without
checking its signature, and a token from a Secret names `kubernetes/serviceaccount` in `iss` whatever the `issuer`
(Context), so the token never becomes a second source of the issuer. The agent logs one warning for a token from a
Secret and another for a wrong `issuer`, so the operator knows whether to change the token file or `issuer` (R29).

`audience` has no default, so a file for the provider `identity-provider` states whether `aud` is checked. The
platform's Keycloak has no audience mapper that names the services of an installation, so a file for it sets `ignore`,
which R6 allows. The name of the mode says that a token with any `aud`, or with none, passes the check, a token issued
for another service included (R26). The provider `kubernetes` has no `audience`. Every Pod can hold a token that the API
server issues for its own audience, and every Kubernetes token is an M2M token (ADR-0092 R7). A provider file that chose
the audience of the API server would make that token an M2M token, so ADR-0094 R14 checks the same `aud` in every
Kubernetes token, whatever the provider files hold (R6).

### Alternatives considered

- **A1. Name the providers file with a setting, as `AUTHZ_TRUSTED_PROVIDERS_FILE` does.** Rejected by R1: every
  deployment mounts the files at one path, so the setting would only be one more value that a deployment and the agent
  have to agree on.
- **A2. Mark the provider of the API server with `kubernetes: true` and accept any key.** Rejected by R6 and R22: the
  kind of a token would follow from a member that a file can set on any provider, and the key and the mark could
  disagree. This reverses ADR-0091 R6 and the choice of ADR-0094 that the mark, not the name of the provider, decides
  which tokens are Kubernetes tokens.
- **A3. Accept any key, and choose the checks of a provider with a member of its own, such as `kind`.** Rejected by R6
  and R22: each kind of token has one provider in this stage, so the member could only repeat the key or contradict it.
- **A4. Find the keys through OIDC discovery under the issuer.** Rejected by R23: the server of the discovery document,
  not the configuration, would choose the address of the keys, and in one cloud the address in the `iss` of the API
  server cannot be reached from inside the cluster. This reverses ADR-0091 R4 and ADR-0094 R6.
- **A5. Take the realm from the part of `iss` after the last slash, and leave the host uncompared.** Rejected by R19:
  a token that names any server would start a load at the configured Keycloak, and the `iss` of a verified token could
  name a server that the configuration does not. This reverses ADR-0091 R3 and the answer on the trusted realms in the
  questionnaire of 2026-11-03.
- **A6. Take the issuer of the provider `kubernetes` from the `iss` of the token in `jwksBearerTokenFile`.** Rejected
  by R6: the provider file states the issuer, and `jwksBearerTokenFile` is optional, so the agent cannot rely on it to
  learn the issuer. This reverses ADR-0094 R4 and the answer on the issuer of the API server in the questionnaire of
  2026-11-03.
- **A7. Require `jwksBearerTokenFile` wherever the provider files hold the provider `kubernetes`.** Rejected by R6: a
  cluster that serves its keys to an anonymous request needs no token, and the Pod then holds no credential for the API
  server. This reverses ADR-0094 R5 and the part of Option 2 under which a provider of the API server without a token
  file stops the start. The architect agreed to Option 2 in #305 on 2026-11-18.
- **A8. Drop the provider `kubernetes` when the file that its `jwksBearerTokenFile` names is missing.** Rejected by
  R14: the readiness probe would pass while the agent refuses every token that the API server signs.
- **A9. Give `readinessRealms` the default `cloud-common`.** Rejected by R13: the agent would carry the name of a realm
  of the platform's Keycloak, and a file for any other server would have to work around it. This reverses ADR-0091
  R15.
- **A10. Resolve the names in `readinessRealms` through tenant-manager, as for `AUTHZ_IDP_REALMS`.** Rejected by R12:
  the agent runs where no tenant-manager exists, and a token carries the realm name, not the display name of its
  tenant.
- **A11. Never check the `aud` of a Keycloak token, whatever the provider file states.** Rejected by R6 and R26: the
  provider file decides for the provider `identity-provider`, in both headers, so a Keycloak that adds an audience for
  the services gets the check without a change of the agent. This reverses ADR-0091 R49 and departs from the answer on
  the `aud` of a Keycloak token in the questionnaire of 2026-11-03.
- **A12. Let one `iss` match two providers, and prefer one of them.** Rejected by R17: the source of a token would
  depend on a rule of precedence that an operator has to know. This reverses the precedence of a provider over the
  realm rule in ADR-0091 R7.
- **A13. Keep the tokens of a `single` provider `identity-provider` from being M2M tokens, as ADR-0092 R8 did for a
  file token.** Rejected by R22: the key alone decides the kind, so both types of the provider `identity-provider` give
  an identity-provider token, and ADR-0092 R6 and R21 decide whether it is an M2M token. This reverses ADR-0092 R8.
- **A16. Give every provider a limit of its own on the tokens it accepts, such as the namespaces of the installation for
  the API server of the agent's cluster, in place of a kind of token.** Rejected by R22: no installation needs the
  tokens of another cluster in this stage, and such a limit would change ADR-0094 well beyond one rule. A later record
  can give each provider a limit of its own.
- **A17. Keep `providers` as a list of objects, each named by a member `id`.** Rejected by R6: a misspelled `id` gets
  an error from every branch of the schema rather than one error that names it, and two providers with one `id` in one
  file need a check of their own, where R3 already refuses one key twice in one file.
- **A18. Refuse a token that holds the claim `kubernetes.io` and whose source is not the provider `kubernetes`, with
  `TOKEN_KUBERNETES_CLAIM_NOT_ALLOWED`.** Rejected by R22: the claim is whatever the signer puts in the token, and the
  architect decided on 2026-11-25 that a token of any provider may hold it, with the checks of a Kubernetes token
  following the provider. This reverses the refusal by the claim in the answer of 2026-11-18 in #305.
- **A19. Stop the start when a provider `identity-provider` names an in-cluster address in `issuer`, `issuerTemplate`,
  or `jwksUri`.** The architect decided on 2026-11-25 that the check of an in-cluster address stays only where the token
  for the API server goes (R28): a provider `identity-provider` that names the API server is a mistake of the provider
  file, as a wrong issuer is (Negative). This reverses ADR-0094 R13.
- **A20. Stop the start, or keep the Pod not ready, when the `issuer` of the provider `kubernetes` differs from the
  `iss` of the token in `jwksBearerTokenFile`.** Rejected by R29: the provider file is the only source of the issuer
  (R6), the agent reads the token without checking its signature, and a token from a Secret names another `iss` even
  when the `issuer` is right (Context).
- **A21. Let a provider file choose the audience of the provider `kubernetes`, with the mode `matchAny` and `values` of
  its own.** Rejected by R6 and ADR-0094 R14: every Pod in the namespaces of the installation can hold a token that the
  API server issues for its own audience, and a file that listed the audience of the API server would make that token an
  M2M token.
- **A22. Skip every entry of the provider directory that is not a provider file.** Rejected by R2: a provider file with
  a misspelled name or extension would drop its provider in a Pod that reports ready, and nothing would show why every
  token of that provider is refused. This reverses the skip of a directory named `*.json` that the architect accepted on
  2026-11-25.

## Consequences

Positive:

- A Keycloak without `/auth`, or at another address, needs another provider file and no change of the agent (R6, R19,
  R23).
- A misspelled key or member of a provider file gets an error that names it and the accepted ones, and an editor that
  reads JSON Schema validates and completes a provider file that names the schema in `$schema` (R6, R18).

Negative:

- A file in the former format of ADR-0091 stops the start (R6), so the agent, its deployments, and the test stands move
  to the provider files in one change.
- An editor checks a provider file against the schema in `main`, which its `$id` names, so a member that `main` gains
  after a release passes in the editor and stops the start of that release of the agent (R6, R18).
- An entry of the provider directory that is not a provider file, such as a backup copy of a provider file or the
  `lost+found` directory of a disk volume, stops the start until it is removed (R2).
- No check tells the platform's Keycloak from another identity provider that a provider file describes under the key
  `identity-provider`. The tokens of such a provider are identity-provider tokens, so they pass the M2M test of ADR-0092
  R6 and R21 with whatever claims that provider signs (R22).
- The keys of a provider `identity-provider` with an http `jwksUri` are protected only by the network of the cluster. A
  host on the path can answer with keys of its own and sign tokens that pass the M2M test of ADR-0092 R6 and R21 for
  every tenant (R6, R23).
- An `iss` that differs from `issuer` or `issuerTemplate` in any byte, such as another case of the host, an explicit
  default port, or a trailing slash, gets `TOKEN_ISSUER_UNKNOWN` (R19, R21). A Keycloak whose tokens name it at another
  address than the provider file, such as its public address, needs that address in `issuer` or `issuerTemplate`, and a
  Keycloak that issues tokens under two addresses cannot be described in this stage.
- After an upgrade to Keycloak 17 without `/auth`, new tokens get `TOKEN_ISSUER_UNKNOWN`, and the reloads of the realms
  that the agent holds fail, until the provider file names the new `issuerTemplate` and the new address of the keys
  (R19, R21, R23).
- A wrong `issuer` or `issuerTemplate` leaves the Pod ready: the keys of the provider still load from `jwksUri`, and
  every token of the provider gets `TOKEN_ISSUER_UNKNOWN`, whose log line names the `iss` of the token (R19, R21, R30).
  For the provider `kubernetes` the issuer is a value set for each cluster, where A6 would read it from a token that the
  kubelet writes, so a wrong value refuses every token that the API server signs, in a Pod that is ready. For the
  provider `kubernetes` with `jwksBearerTokenFile`, R29 logs a warning at the start.
- In a cluster whose DNS domain is not `cluster.local`, the full name of the API server,
  `kubernetes.default.svc.<domain>`, is not an in-cluster address, so a provider `kubernetes` with `jwksBearerTokenFile`
  names `kubernetes.default.svc` in `jwksUri` (R28).
- A `realms` provider `identity-provider` without `readinessRealms` has no required source, so the Pod becomes ready
  before any realm has loaded keys, and a wrong `jwksUri` shows only in the refusals of its tokens and in the warnings
  of ADR-0091 R81 (R13, R25; ADR-0091 R23, R38, R39, R81).
- A provider `kubernetes` without `jwksBearerTokenFile` requests its keys without a token. A standard cluster refuses
  that request (ADR-0094 Context), and the Pod stays not ready (ADR-0091 R19).
- A name in `readinessRealms` that the Keycloak does not hold, such as the display name of a tenant, keeps the Pod not
  ready until the file changes (R12; ADR-0091 R14, R19).
- A change of a provider file takes effect only at the next start (R5).
- A token of a `single` provider `identity-provider` is an identity-provider token (R22), so the M2M test of ADR-0092
  R6 and R21 applies to it, where ADR-0092 R8 kept the tokens of a provider outside the realms of the Keycloak from
  being M2M tokens (A13).
- No rule of this record names the CA that the requests of R23 trust, and the rules of ADR-0091 and ADR-0094 that
  named one went with the requests that this record replaces. A `caFile` now stops the start under R6. An https
  `jwksUri` whose certificate a private CA or the cluster CA signs therefore works only once the agent trusts that CA in
  another way.
- A provider `identity-provider` whose `issuer` or `issuerTemplate` names an API server makes every token of that API
  server an identity-provider token (R22). Where the provider `kubernetes` names the same issuer, R17 stops the start.
  Otherwise, where the keys load without a token, as the public keys of a managed cluster do, the token of a Pod of that
  cluster passes with no namespace check of ADR-0094, and nothing at the start or in a refusal shows the mistake. Where
  the keys need a token, as at the in-cluster address of a standard cluster, they never load, because only the provider
  `kubernetes` may hold `jwksBearerTokenFile` (R6), and a `single` provider then keeps the Pod not ready (R25; ADR-0091
  R19).
- A token of the provider `identity-provider` that holds the claim `kubernetes.io` passes, and policy evaluation gets
  that claim among the verified claims (ADR-0091 R54). Its kind is identity-provider (R22), so no check of ADR-0094
  compared the namespace in it with the namespaces of the installation. A policy that reads that namespace without
  checking the kind trusts what the identity provider wrote.
- A token from a Secret in `jwksBearerTokenFile` gets the warning of R29 at every start, and the `issuer` of the
  provider `kubernetes` is then compared with nothing. A projected token, such as the one that ADR-0094 R26 mounts,
  names the issuer of the API server.
- A provider `kubernetes` without `jwksBearerTokenFile` may name the issuer and the keys of the API server of another
  cluster, because R28 limits the address of its keys only when that member is set (R24, R28). The tokens of that
  cluster are then Kubernetes tokens, ADR-0094 R17 compares only the names of their namespaces, which another cluster
  can also use, and R29 has no token to compare the issuer with.
- An `Incoming-Token` that fails the check of `aud` under R26 or ADR-0094 R14 does not end the request: policy
  evaluation gets the reason code of the failure rather than the claims of that token (ADR-0095 R3).

Follow-ups:

- ADR-0106 ([#330](https://github.com/Netcracker/qubership-authz-agent/pull/330)) decides the CA that the requests of
  R23 trust, in place of the term Cluster CA and the CA half of ADR-0094 R2.
