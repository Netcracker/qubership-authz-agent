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
app.kubernetes.io/part-of: '{{ .Values.APPLICATION_NAME }}'
app.kubernetes.io/managed-by: 'saasDeployer'
app.kubernetes.io/technology: 'go'
{{- end -}}

{{/*
The labels of an object's metadata: the common set plus the deployer's session
id, which the platform's charts put on every object and never on the Pod
template. The id changes with every install session, and a Pod template label
that changes rolls the Pods over on a deploy that changed nothing else.
*/}}
{{- define "authz-agent.objectLabels" -}}
{{ include "authz-agent.commonLabels" . }}
{{- if .Values.DEPLOYMENT_SESSION_ID }}
deployment.netcracker.com/sessionId: '{{ .Values.DEPLOYMENT_SESSION_ID }}'
{{- end }}
{{- end -}}

{{/*
The agent's image. AUTHZ_AGENT_IMAGE wins where it is set; otherwise the
helper computes "{IMAGE_REPOSITORY}/authz-agent:{TAG}".
*/}}
{{- define "authz-agent.serviceImage" -}}
{{- coalesce .Values.AUTHZ_AGENT_IMAGE (printf "%s/authz-agent:%s" .Values.IMAGE_REPOSITORY .Values.TAG) -}}
{{- end -}}

{{/*
Policy pull source for the agent's pull loop: AUTHZ_PAP_CLIENT_SOURCE_URL with a
trailing slash removed. The puller composes the request URL by plain string
concatenation (components/authz-agent/internal/pull/pull.go), so an operator's
trailing slash would produce `//access/v3/config/policySets`. Empty stays
empty, which leaves the pull loop off.
*/}}
{{- define "authz-agent.papSourceURL" -}}
{{- if .Values.AUTHZ_PAP_CLIENT_SOURCE_URL -}}
{{- trimSuffix "/" .Values.AUTHZ_PAP_CLIENT_SOURCE_URL -}}
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
app.kubernetes.io/part-of: '{{ .Values.APPLICATION_NAME }}'
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

These go to port 8080, the agent's public listener, which answers each legacy
route in the shape access-control's clients expect. Routing one of them to the
data API on 8181 instead would return the raw policy document.
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
"M2M Identity and Token Delivery"). If the Secret is missing, the agent cannot
obtain its M2M token, the pull loop never authenticates, and the Pod stays
NotReady indefinitely. Helm cannot verify Secret existence at template time.
*/}}
{{/*
Data API write-path authentication token (authz-agent-ADR-0077).

Generated once per install (randAlphaNum 32) and preserved across upgrades via
the Helm `lookup` function, so that a client holding the old token is not cut
off by a `helm upgrade`. When the Secret already exists, its current value is
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
{{/*
The access-control stub, authz-policy-admin, is a chart of its own,
helm-templates/authz-policy-admin. A values file written for the time it was
part of this chart would render without a word here: no stub would be deployed,
and the agent would pull from nowhere.
*/}}
{{- $stubKeys := list -}}
{{- range keys .Values -}}
{{- if hasPrefix "AUTHZ_POLICY_ADMIN_" . -}}
{{- $stubKeys = append $stubKeys . -}}
{{- end -}}
{{- end -}}
{{- if $stubKeys -}}
{{- fail (printf "this chart no longer deploys authz-policy-admin and does not read %s. Install helm-templates/authz-policy-admin beside this chart and point AUTHZ_PAP_CLIENT_SOURCE_URL at its Service, http://authz-policy-admin:18090 with that chart's defaults." (join ", " (sortAlpha $stubKeys))) -}}
{{- end -}}
{{/*
The platform's HorizontalPodAutoscaler template renders maxReplicas from
HPA_MAX_REPLICAS with no default, and the API server rejects an autoscaler
without one. minReplicas falls back to REPLICAS and the target to 75, so this
is the one key an enabled autoscaler cannot do without; every resource profile
sets it.
*/}}
{{- if and .Values.HPA_ENABLED (not (hasKey .Values "HPA_MAX_REPLICAS")) -}}
{{- fail "HPA_ENABLED=true requires HPA_MAX_REPLICAS: maxReplicas has no default in the platform's HorizontalPodAutoscaler template, and the API server rejects an autoscaler without it. The resource profiles set it." -}}
{{- end -}}
{{/*
The template renders a scaling policy whenever its *_VALUE is set and takes
the period as 0 when *_PERIOD_SECONDS is not, which leaves periodSeconds empty
in the render. The API server rejects that, with the autoscaler enabled or
not, since the policies render either way.
*/}}
{{- range list "HPA_SCALING_UP_PODS" "HPA_SCALING_UP_PERCENT" "HPA_SCALING_DOWN_PODS" "HPA_SCALING_DOWN_PERCENT" -}}
{{- if and (index $.Values (printf "%s_VALUE" .)) (not (hasKey $.Values (printf "%s_PERIOD_SECONDS" .))) -}}
{{- fail (printf "%s_VALUE is set without %s_PERIOD_SECONDS: the platform's HorizontalPodAutoscaler template then renders the policy with an empty periodSeconds, which the API server rejects." . .) -}}
{{- end -}}
{{- end -}}
{{/*
Values this chart no longer reads: the per-container parameters of the
five-container Pod (authz-agent-ADR-0080), and the AUTHZ_AGENT_-prefixed sizing
that the platform names CPU_REQUEST, CPU_LIMIT, MEMORY_REQUEST and MEMORY_LIMIT.
`additionalProperties` is true, so a values file that still carries them renders
without a word and the agent silently takes the defaults of this chart: an
install passing its own copy of an old prod profile would drop from a 13Gi
memory limit to 700Mi in one upgrade. Name them instead.
*/}}
{{- $removed := list
  "ENVOY_IMAGE" "OPA_IMAGE" "PAP_CLIENT_IMAGE" "COLLECTOR_IMAGE" "TOKEN_FETCHER_IMAGE"
  "AUTHZ_SINGLE_SERVICE_ENABLED"
  "ENVOY_CPU_REQUEST" "ENVOY_CPU_LIMIT" "ENVOY_MEM_REQUEST" "ENVOY_MEM_LIMIT"
  "OPA_CPU_REQUEST" "OPA_CPU_LIMIT" "OPA_MEM_REQUEST" "OPA_MEM_LIMIT"
  "PAP_CLIENT_CPU_REQUEST" "PAP_CLIENT_CPU_LIMIT" "PAP_CLIENT_MEM_REQUEST" "PAP_CLIENT_MEM_LIMIT"
  "COLLECTOR_CPU_REQUEST" "COLLECTOR_CPU_LIMIT" "COLLECTOR_MEM_REQUEST" "COLLECTOR_MEM_LIMIT"
  "AUTHZ_AGENT_CPU_REQUEST" "AUTHZ_AGENT_CPU_LIMIT" "AUTHZ_AGENT_MEM_REQUEST" "AUTHZ_AGENT_MEM_LIMIT" -}}
{{- $carried := list -}}
{{- range $removed -}}
{{- if hasKey $.Values . -}}
{{- $carried = append $carried . -}}
{{- end -}}
{{- end -}}
{{- if $carried -}}
{{- fail (printf "this chart no longer reads these values: %s. The agent Pod is one container since authz-agent-ADR-0080, sized by CPU_REQUEST, CPU_LIMIT, MEMORY_REQUEST, MEMORY_LIMIT, AUTHZ_AGENT_EPHEMERAL_STORAGE_REQUEST and AUTHZ_AGENT_EPHEMERAL_STORAGE_LIMIT, with its image in AUTHZ_AGENT_IMAGE. Set those and drop these; without this check the Pod would take this chart's defaults." (join ", " $carried)) -}}
{{- end -}}
{{- end -}}

{{/*
The platform's CPU quantity conversion, taken with its HorizontalPodAutoscaler
template: `350m` gives 350, `15` gives 15000.
*/}}
{{- define "to_millicores" -}}
  {{- $value := toString . -}}
  {{- if hasSuffix "m" $value -}}
    {{ trimSuffix "m" $value }}
  {{- else -}}
    {{ mulf $value 1000 }}
  {{- end -}}
{{- end -}}
