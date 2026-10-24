{{/*
The labels every object of a part carries. The selectors keep the single
label app: <name>, so the Makefile's deploy/<name> and a reader's
kubectl -l app=<name> address a part by its Service name.
Takes a dict: root (the chart context), name, component.
*/}}
{{- define "authz-test-stand.labels" -}}
app: {{ .name }}
app.kubernetes.io/name: {{ .name }}
app.kubernetes.io/instance: {{ .root.Release.Name }}
app.kubernetes.io/component: {{ .component }}
app.kubernetes.io/part-of: authz-test-stand
app.kubernetes.io/managed-by: {{ .root.Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .root.Chart.Name .root.Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
The Pod security context of every part: a non-root user and the runtime's
default seccomp profile, as the restricted Pod Security Standard requires.
No runAsUser: each image names its own non-root user, and on OpenShift the
restricted SCC assigns a uid from the namespace range and rejects a pinned one.
*/}}
{{- define "authz-test-stand.podSecurityContext" -}}
runAsNonRoot: true
seccompProfile:
  type: RuntimeDefault
{{- end }}

{{/*
The container security context of every part. Takes the value of
readOnlyRootFilesystem: true for every container except Keycloak, which
writes its database and its build under /opt/keycloak.
*/}}
{{- define "authz-test-stand.containerSecurityContext" -}}
allowPrivilegeEscalation: false
readOnlyRootFilesystem: {{ . }}
capabilities:
  drop:
    - ALL
{{- end }}
