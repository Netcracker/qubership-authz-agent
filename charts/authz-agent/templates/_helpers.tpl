{{/*
authz-agent chart helpers.

The chart does not depend on cloudbss-lib (BSS-only). Labels and instance
naming are inlined here so every rendered manifest carries the
sector-mandatory app.kubernetes.io/* labels per the Pdkg-alignment
contract (UNM-157915).
*/}}

{{- define "authz-agent.serviceName" -}}
{{- coalesce .Values.DEPLOYMENT_RESOURCE_NAME .Values.SERVICE_NAME -}}
{{- end -}}

{{- define "authz-agent.instance" -}}
{{- cat (coalesce .Values.DEPLOYMENT_RESOURCE_NAME .Values.SERVICE_NAME) "-" .Values.NAMESPACE | nospace | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "authz-agent.commonLabels" -}}
name: '{{ include "authz-agent.serviceName" . }}'
app.kubernetes.io/name: '{{ .Values.SERVICE_NAME }}'
app.kubernetes.io/instance: '{{ include "authz-agent.instance" . }}'
{{/*
Truncated to the 63-byte Kubernetes label limit. The value is usually a
pipeline-generated version, and a branch build produces strings longer than
that: `0.0.0-feature-some-long-branch-name-20260728.204756-14889036` is
already over 63 bytes, and the API server rejects every object carrying it —
`metadata.labels: Invalid value: ...: must be no more than 63 bytes`, i.e. the
whole release fails to install.
`trimSuffix "-"` keeps the truncated value a legal label (it may not end in a
separator).
*/}}
app.kubernetes.io/version: '{{ .Values.ARTIFACT_DESCRIPTOR_VERSION | trunc 63 | trimSuffix "-" | trimSuffix "." | trimSuffix "_" }}'
app.kubernetes.io/component: 'backend'
app.kubernetes.io/part-of: 'Platform-Core-Security'
app.kubernetes.io/managed-by: 'saasDeployer'
app.kubernetes.io/technology: 'go'
{{- end -}}

{{/*
Image references. If a per-image override is set in values
(ENVOY_IMAGE, PAP_CLIENT_IMAGE, COLLECTOR_IMAGE, TOKEN_FETCHER_IMAGE), it wins.
Otherwise the helper computes
"{IMAGE_REPOSITORY}/authz-agent-{envoy|pap-client|collector|token-fetcher}:{TAG}".
*/}}

{{- define "authz-agent.envoyImage" -}}
{{- coalesce .Values.ENVOY_IMAGE (printf "%s/authz-agent-envoy:%s" .Values.IMAGE_REPOSITORY .Values.TAG) -}}
{{- end -}}

{{/*
OPA runs as the vanilla upstream image, pinned by digest.
The digest pin (`latest-static` is not a pin) is the default; OPA_IMAGE
overrides it when a different OPA build is needed.  OPA version 1.14.0.
*/}}
{{- define "authz-agent.opaImage" -}}
{{- coalesce .Values.OPA_IMAGE "openpolicyagent/opa@sha256:b326c40be4255ff568350542d546f70950b8d321fbbc59e604918230c0520b16" -}}
{{- end -}}

{{/*
pap-client image: Policy Administration Point client (bootstrap, pull, push).
Image name follows the Pod-container naming rule: authz-agent-<container>.
*/}}
{{- define "authz-agent.papClientImage" -}}
{{- coalesce .Values.PAP_CLIENT_IMAGE (printf "%s/authz-agent-pap-client:%s" .Values.IMAGE_REPOSITORY .Values.TAG) -}}
{{- end -}}

{{- define "authz-agent.collectorImage" -}}
{{- coalesce .Values.COLLECTOR_IMAGE (printf "%s/authz-agent-collector:%s" .Values.IMAGE_REPOSITORY .Values.TAG) -}}
{{- end -}}

{{/*
Optional access-control stub (authz-agent-ADR-0073). Rendered only when
AUTHZ_POLICY_ADMIN_ENABLED is true; see templates/authz-policy-admin.yaml.
*/}}

{{- define "authz-agent.authzPolicyAdminName" -}}
{{- printf "%s-authz-policy-admin" (include "authz-agent.serviceName" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
The stub's labels MUST NOT repeat the agent's `name` label.
`authz-agent.commonLabels` emits `name: <serviceName>`, and templates/service.yaml
selects on exactly that key, so a stub Pod carrying it would be admitted to the
agent's Service on ports 8080/8181 — where the stub serves nothing — and a share
of every authorization request would answer 404. `app.kubernetes.io/name` is kept
distinct for the same reason: any future label-based selector (for example the
ServiceMonitor that MONITORING_ENABLED is meant to bring back) must not sweep the
stub in with the agent.
*/}}
{{- define "authz-agent.authzPolicyAdminSelector" -}}
name: '{{ include "authz-agent.authzPolicyAdminName" . }}'
{{- end -}}

{{- define "authz-agent.authzPolicyAdminLabels" -}}
{{ include "authz-agent.authzPolicyAdminSelector" . }}
app.kubernetes.io/name: '{{ .Values.SERVICE_NAME }}-authz-policy-admin'
app.kubernetes.io/instance: '{{ include "authz-agent.instance" . }}'
app.kubernetes.io/version: '{{ .Values.ARTIFACT_DESCRIPTOR_VERSION | trunc 63 | trimSuffix "-" | trimSuffix "." | trimSuffix "_" }}'
app.kubernetes.io/component: 'test-double'
app.kubernetes.io/part-of: 'Platform-Core-Security'
app.kubernetes.io/managed-by: 'saasDeployer'
app.kubernetes.io/technology: 'go'
{{- end -}}

{{- define "authz-agent.authzPolicyAdminImage" -}}
{{- coalesce .Values.AUTHZ_POLICY_ADMIN_IMAGE (printf "%s/authz-policy-admin:%s" .Values.IMAGE_REPOSITORY .Values.TAG) -}}
{{- end -}}

{{- define "authz-agent.tokenFetcherImage" -}}
{{- coalesce .Values.TOKEN_FETCHER_IMAGE (printf "%s/authz-agent-token-fetcher:%s" .Values.IMAGE_REPOSITORY .Values.TAG) -}}
{{- end -}}

{{/*
Policy pull source for the pap-client container.

Precedence: an explicitly configured AUTHZ_PAP_CLIENT_SOURCE_URL always wins — enabling
the stub while pointing the agent at a real access-control is a legitimate
cutover setup, and the stub is then simply idle. Otherwise, when the stub is
enabled, the agent is wired to its Service automatically so that a plain
`helm install --set AUTHZ_POLICY_ADMIN_ENABLED=true` produces a working pull loop.

`trimSuffix "/"` matters: PolicyPuller composes the request URL by plain string
concatenation (components/pap-client/internal/policyadmin/policy_puller.go), so an operator's
trailing slash would produce `//access/v3/config/policySets`.
*/}}
{{- define "authz-agent.papSourceURL" -}}
{{- if .Values.AUTHZ_PAP_CLIENT_SOURCE_URL -}}
{{- trimSuffix "/" .Values.AUTHZ_PAP_CLIENT_SOURCE_URL -}}
{{- else if .Values.AUTHZ_POLICY_ADMIN_ENABLED -}}
{{- printf "http://%s:%d" (include "authz-agent.authzPolicyAdminName" .) (int .Values.AUTHZ_POLICY_ADMIN_PORT) -}}
{{- end -}}
{{- end -}}

{{/*
Trusted providers (authz-agent-ADR-0075).

When AUTHZ_TRUSTED_PROVIDERS is set it wins outright — an operator naming their
own providers has decided something the chart cannot second-guess.

When it is empty the list is built from the platform's own convention rather
than left empty: the IdP base URL comes from IDENTITY_PROVIDER_URL and the
issuer is composed as `<base>/auth/realms/<realm>`, which is exactly what the
security libraries do (IdentityProviderConfig.java, security/token/keycloak.go).
The composed issuer is only the address to fetch keys from; the `iss` claim is
not checked at all any more, so a realm reached through a gateway hostname
verifies the same way.

`cloud-common` — the platform M2M realm — is the one entry marked required, so a
Pod that cannot reach it does not report Ready. The rest are optional because
most namespaces genuinely do not have them. No entry carries `audiences`: a
generated provider accepts any token its realm's keys signed, and separating
external subjects from internal ones is left to policies and roles.
*/}}
{{- define "authz-agent.trustedProviders" -}}
{{- if .Values.AUTHZ_TRUSTED_PROVIDERS -}}
{{- toJson .Values.AUTHZ_TRUSTED_PROVIDERS -}}
{{- else -}}
{{- $base := trimSuffix "/" (required "IDENTITY_PROVIDER_URL must not be empty when AUTHZ_TRUSTED_PROVIDERS is unset" .Values.IDENTITY_PROVIDER_URL) -}}
{{- $providers := list -}}
{{- range .Values.AUTHZ_IDP_REALMS -}}
{{- $entry := dict "id" . "issuer" (printf "%s/auth/realms/%s" $base .) -}}
{{- if eq . "cloud-common" -}}
{{- $_ := set $entry "required" true -}}
{{- end -}}
{{- $providers = append $providers $entry -}}
{{- end -}}
{{- toJson $providers -}}
{{- end -}}
{{- end -}}

{{/*
The bootstrap threshold that goes with the list above.

A generated list names four realms and most namespaces have one, so strict mode
would hold every Pod out of its Service on realms that were never expected to be
there. Readiness for a generated list is carried by the `required` marker on
cloud-common instead. An explicitly configured list keeps whatever the operator
set.
*/}}
{{- define "authz-agent.jwksBootstrapRequired" -}}
{{- if .Values.AUTHZ_TRUSTED_PROVIDERS -}}
{{- .Values.AUTHZ_JWKS_BOOTSTRAP_REQUIRED -}}
{{- else -}}
false
{{- end -}}
{{- end -}}

{{/*
Service-mesh route registration (authz-agent-ADR-0074).

Labels required by the platform: `processed-by-operator` is what makes
core-operator pick the CR up at all, and `deployer.cleanup/allow` is what lets
the deployer remove the routes when the release goes away. Copied from the
access-control chart, which is the reference implementation for these CRs.
*/}}
{{- define "authz-agent.meshLabels" -}}
app.kubernetes.io/name: '{{ .Values.SERVICE_NAME }}'
app.kubernetes.io/part-of: 'Platform-Core-Security'
app.kubernetes.io/managed-by: '{{ .Values.MANAGED_BY }}'
app.kubernetes.io/processed-by-operator: 'core-operator'
deployer.cleanup/allow: 'true'
{{- if .Values.DEPLOYMENT_SESSION_ID }}
deployment.netcracker.com/sessionId: '{{ .Values.DEPLOYMENT_SESSION_ID }}'
{{- end }}
{{- end -}}

{{/*
The access-control-compatible check API, as far as this agent implements it.

Prefixes (not exact paths) on purpose — `/access/v1/check/resource` also covers
`/access/v1/check/resource/bulk` and `.../bulk/operations`, and `/preview/v1/check`
covers the preview bulk-operations route. This is the same prefix set
access-control registers on its public and private gateways, minus everything
this agent does not serve (its whole management surface).

These go through Envoy on port 8080: each legacy route carries a per-route Lua
filter that rewrites the request and the response, so bypassing Envoy here would
return raw OPA documents instead of the compatible shape.
*/}}
{{- define "authz-agent.meshCheckRules" -}}
- match:
    prefix: /access/v1/check/resource
- match:
    prefix: /preview/v1/check
- match:
    prefix: /access/v2/check/resource
- match:
    prefix: /preview/v2/check
{{- end -}}

{{/*
Cross-value guards. These combinations render superficially valid manifests but
do nothing useful at runtime — they fail at template time instead.

Note on KUBERNETES_M2M_ENABLED=false (Keycloak mode): The Secret
'{{ .Values.SERVICE_NAME }}-client-credentials' MUST exist before helm install.
It is provisioned externally by the platform (security-scripts or manual creation
with label core.netcracker.com/secret-type=m2m; see docs/architecture.md §
"M2M Identity and Token Delivery"). If the Secret is missing, the token-fetcher
sidecar cannot start, the startupProbe never passes, and the Pod stays NotReady
indefinitely.  Helm cannot verify Secret existence at template time.
*/}}
{{/*
OPA write-path authentication token (authz-agent-ADR-0077).

Generated once per install (randAlphaNum 32) and preserved across upgrades via
the Helm `lookup` function so that pap-client does not lose sync with OPA
after a `helm upgrade`. When the Secret already exists, its current value is
reused; on a fresh install a new random value is generated.
*/}}
{{- define "authz-agent.opaAuthToken" -}}
{{- $secretName := printf "%s-opa-auth" (include "authz-agent.serviceName" .) -}}
{{- $existing := lookup "v1" "Secret" .Release.Namespace $secretName -}}
{{- if and $existing $existing.data (index $existing.data "token") -}}
{{- index $existing.data "token" | b64dec -}}
{{- else -}}
{{- randAlphaNum 32 -}}
{{- end -}}
{{- end -}}

{{- define "authz-agent.validateValues" -}}
{{- if and .Values.AUTHZ_POLICY_ADMIN_ENABLED .Values.AUTHZ_POLICY_CONFIGMAP -}}
{{- fail (printf "AUTHZ_POLICY_ADMIN_ENABLED=true conflicts with AUTHZ_POLICY_CONFIGMAP=%s: pap-client selects ConfigMap mount mode when /etc/authz/policies exists at startup and disables the pull loop entirely (authz-agent-ADR-0072), so the stub would be deployed, given a volume, and never polled. Pick one delivery mode." .Values.AUTHZ_POLICY_CONFIGMAP) -}}
{{- end -}}
{{- if and .Values.AUTHZ_POLICY_ADMIN_ENABLED (eq (int .Values.AUTHZ_PAP_CLIENT_PULL_INTERVAL) 0) -}}
{{- fail "AUTHZ_POLICY_ADMIN_ENABLED=true requires AUTHZ_PAP_CLIENT_PULL_INTERVAL > 0: 0 disables the pull loop, so the agent would never fetch from the stub." -}}
{{- end -}}
{{- end -}}
