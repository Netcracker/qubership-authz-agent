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
verifies the same way. authz-agent.validateValues refuses an
IDENTITY_PROVIDER_URL that is empty or has no http or https scheme or no host.

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
{{- $base := .Values.IDENTITY_PROVIDER_URL | default "" | toString | trimSuffix "/" -}}
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
The access-control-compatible check API, as far as this agent implements it.

Prefixes (not exact paths) on purpose — `/access/v1/check/resource` also covers
`/access/v1/check/resource/bulk` and `.../bulk/operations`, and `/preview/v1/check`
covers the preview bulk-operations route. This is the same prefix set
access-control registers on its public and private gateways, minus everything
this agent does not serve (its whole management surface).

These go to port 8080, the agent's public listener, which answers each legacy
route in the shape access-control's clients expect.
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

Note on AUTHZ_OUTGOING_TOKEN_SOURCE=client-credentials, the default: The Secret
'{{ .Values.SERVICE_NAME }}-client-credentials' MUST exist before helm install.
It is provisioned externally by the platform (security-scripts or manual creation
with label core.netcracker.com/secret-type=m2m). If the Secret is missing, the
agent cannot obtain its client credentials token, the pull loop never
authenticates, and the Pod stays NotReady indefinitely. Helm cannot verify
Secret existence at template time.
*/}}
{{/*
authz-agent.outgoingTokenSource is AUTHZ_OUTGOING_TOKEN_SOURCE, which the values
schema limits to client-credentials and token-file.
*/}}
{{- define "authz-agent.outgoingTokenSource" -}}
{{- .Values.AUTHZ_OUTGOING_TOKEN_SOURCE | default "client-credentials" -}}
{{- end -}}

{{/*
authz-agent.outgoingTokenURL is the token endpoint of client-credentials: the
value AUTHZ_OUTGOING_TOKEN_URL where it is set, and otherwise
IDENTITY_PROVIDER_URL, less one trailing slash, followed by the token path of
the realm cloud-common.
*/}}
{{- define "authz-agent.outgoingTokenURL" -}}
{{- if .Values.AUTHZ_OUTGOING_TOKEN_URL -}}
{{- .Values.AUTHZ_OUTGOING_TOKEN_URL -}}
{{- else -}}
{{- .Values.IDENTITY_PROVIDER_URL | default "" | toString | trimSuffix "/" -}}/auth/realms/cloud-common/protocol/openid-connect/token
{{- end -}}
{{- end -}}

{{- define "authz-agent.validateValues" -}}
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
The chart builds two values from IDENTITY_PROVIDER_URL. With
AUTHZ_OUTGOING_TOKEN_SOURCE client-credentials and AUTHZ_OUTGOING_TOKEN_URL
empty, the Deployment sets AUTHZ_OUTGOING_TOKEN_URL to it followed by the token
path of the realm cloud-common, whatever AUTHZ_TRUSTED_PROVIDERS holds. With
AUTHZ_TRUSTED_PROVIDERS empty, the trusted-providers ConfigMap gets the issuer
`<base>/auth/realms/<realm>` for each realm in AUTHZ_IDP_REALMS, whatever
AUTHZ_OUTGOING_TOKEN_SOURCE is. Where the chart builds either one, this check
refuses a value that is empty or has no http or https scheme or no host. The
message has one sentence for each value built, naming the setting that makes the
chart build it.

The agent refuses such a token endpoint when it starts, with an error that names
AUTHZ_OUTGOING_TOKEN_URL, which the operator did not set when the chart builds
it, so this check names IDENTITY_PROVIDER_URL instead. Like that error, the
check leaves the value out of the message, because a URL can hold a password.
The agent accepts such an issuer and fails its discovery, so the provider never
bootstraps. A generated cloud-common provider is marked required, and without it
the agent returns 503 on /health and /ready.

The scheme and the host are read with regexMatch, which returns false for a
value it does not match and never stops the render with an error. urlParse would
stop the render on any value Go's url.Parse refuses, such as 10.0.0.5:8080, with
an error that names no chart value and quotes the input.

The host follows `//` and an optional user that ends at `@`. It is either any
text in brackets, which is how an IPv6 address is written, or a name without
brackets. An optional `:port` may follow either form. Any other value with an
http or https scheme and a host renders. In a token endpoint, the agent refuses
at start a user, a query, a fragment, a port outside 1 to 65535, or a character
outside RFC 3986, such as a newline. The agent does not check an issuer at
start, and the discovery of an issuer with a port that is not a number, or with
a newline, fails.
*/}}
{{- $uses := list -}}
{{- if and (eq (include "authz-agent.outgoingTokenSource" .) "client-credentials") (not .Values.AUTHZ_OUTGOING_TOKEN_URL) -}}
{{- $uses = append $uses "While AUTHZ_OUTGOING_TOKEN_SOURCE is client-credentials and AUTHZ_OUTGOING_TOKEN_URL is empty, their defaults, the chart builds the agent's token endpoint AUTHZ_OUTGOING_TOKEN_URL from it." -}}
{{- end -}}
{{- if and (not .Values.AUTHZ_TRUSTED_PROVIDERS) .Values.AUTHZ_IDP_REALMS -}}
{{- $uses = append $uses "While AUTHZ_TRUSTED_PROVIDERS is empty, its default, the chart builds the issuer of each realm in AUTHZ_IDP_REALMS from it." -}}
{{- end -}}
{{- if $uses -}}
{{- $idp := .Values.IDENTITY_PROVIDER_URL | default "" | toString -}}
{{- $problem := "" -}}
{{- if not $idp -}}
{{- $problem = "is empty" -}}
{{- else if not (regexMatch "^(?i)https?:" $idp) -}}
{{- $problem = "has no http or https scheme" -}}
{{- else if not (regexMatch "^(?is)https?://([^/?#]*@)?(\\[[^\\]/?#@]+\\]|[^:/?#@\\[\\]]+)(:[^/?#@]*)?([/?#].*)?$" $idp) -}}
{{- $problem = "has no host" -}}
{{- end -}}
{{- if $problem -}}
{{- fail (printf "IDENTITY_PROVIDER_URL %s. %s Set it to an http or https URL with a host: the base URL of the platform identity provider, without a realm, such as http://identity-provider:8080." $problem (join " " $uses)) -}}
{{- end -}}
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
