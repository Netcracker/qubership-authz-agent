{{/*
authz-policy-admin chart helpers. Labels and instance naming are inlined here,
as in the authz-agent chart, so every rendered manifest carries the
app.kubernetes.io/* labels the platform expects.
*/}}

{{- define "authz-policy-admin.serviceName" -}}
{{- coalesce .Values.DEPLOYMENT_RESOURCE_NAME .Values.SERVICE_NAME -}}
{{- end -}}

{{- define "authz-policy-admin.instance" -}}
{{- cat (coalesce .Values.DEPLOYMENT_RESOURCE_NAME .Values.SERVICE_NAME) "-" .Values.NAMESPACE | nospace | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
The `name` label is what the Service and the Deployment select on. It is this
chart's own service name, so a stub Pod is never admitted to the agent's
Service, which selects on the agent's.
*/}}
{{- define "authz-policy-admin.commonLabels" -}}
name: '{{ include "authz-policy-admin.serviceName" . }}'
app.kubernetes.io/name: '{{ .Values.SERVICE_NAME }}'
app.kubernetes.io/instance: '{{ include "authz-policy-admin.instance" . }}'
{{/*
Truncated to the 63-byte Kubernetes label limit: a branch build produces a
version longer than that, and the API server rejects every object carrying it.
`trimSuffix "-"` keeps the truncated value a legal label.
*/}}
app.kubernetes.io/version: '{{ .Values.ARTIFACT_DESCRIPTOR_VERSION | trunc 63 | trimSuffix "-" | trimSuffix "." | trimSuffix "_" }}'
app.kubernetes.io/component: 'test-double'
app.kubernetes.io/part-of: '{{ .Values.APPLICATION_NAME }}'
app.kubernetes.io/managed-by: 'saasDeployer'
app.kubernetes.io/technology: 'go'
{{- end -}}

{{/*
The labels of an object's metadata: the common set plus the deployer's session
id, which the platform's charts put on every object and never on the Pod
template. The id changes with every install session, and a Pod template label
that changes rolls the Pod over on a deploy that changed nothing else.
*/}}
{{- define "authz-policy-admin.objectLabels" -}}
{{ include "authz-policy-admin.commonLabels" . }}
{{- if .Values.DEPLOYMENT_SESSION_ID }}
deployment.netcracker.com/sessionId: '{{ .Values.DEPLOYMENT_SESSION_ID }}'
{{- end }}
{{- end -}}

{{/*
Labels of the mesh route CR (authz-agent-ADR-0074). `processed-by-operator` is
what makes core-operator pick the CR up at all, and `deployer.cleanup/allow` is
what lets the deployer remove the route when the release goes away.
*/}}
{{- define "authz-policy-admin.meshLabels" -}}
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
Values this chart does not read: the sizing keys the stub had inside the
authz-agent chart, which the platform names CPU_REQUEST, CPU_LIMIT,
MEMORY_REQUEST and MEMORY_LIMIT; AUTHZ_POLICY_ADMIN_ENABLED, which a chart that
is the stub has no use for; and the AUTHZ_POLICY_ADMIN_IMAGE override, since the
image is IMAGE_REPOSITORY:TAG as on the platform's charts. `additionalProperties` is true, so a values
file that still carries them would render without a word and the Pod would
take this chart's defaults.
*/}}
{{- define "authz-policy-admin.validateValues" -}}
{{- $removed := list "AUTHZ_POLICY_ADMIN_ENABLED" "AUTHZ_POLICY_ADMIN_IMAGE" "AUTHZ_POLICY_ADMIN_CPU_REQUEST" "AUTHZ_POLICY_ADMIN_CPU_LIMIT" "AUTHZ_POLICY_ADMIN_MEM_REQUEST" "AUTHZ_POLICY_ADMIN_MEM_LIMIT" -}}
{{- $carried := list -}}
{{- range $removed -}}
{{- if hasKey $.Values . -}}
{{- $carried = append $carried . -}}
{{- end -}}
{{- end -}}
{{- if $carried -}}
{{- fail (printf "this chart does not read these values: %s. It is sized by CPU_REQUEST, CPU_LIMIT, MEMORY_REQUEST and MEMORY_LIMIT, and its image is IMAGE_REPOSITORY:TAG; drop the listed keys." (join ", " $carried)) -}}
{{- end -}}
{{- end -}}
