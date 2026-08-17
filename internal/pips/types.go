// Copyright 2024-2026 Netcracker Technology Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package pips

import "encoding/json"

const (
	PipTypeGeneral         = "GENERAL"
	PipTypeFiltered        = "FILTERED"
	PipTypeHeader          = "HEADER"
	PipTypeToken           = "TOKEN"
	PipTypeMapping         = "MAPPING"
	PipTypePermissionScope = "PERMISSION_SCOPE"
	// PipTypeEntitlements is the container-pinned entry materialised at
	// startup from AUTHZ_ENTITLEMENTS_URL + companion env knobs per
	// ADR-0054 / D-AG-11. It cannot be delivered via the pull loop or a
	// mounted ConfigMap: if encountered during conversion it is silently
	// dropped (the container-pinned entry wins) per D-AG-16.
	PipTypeEntitlements = "ENTITLEMENT"

	// EntitlementsPIPName and EntitlementsPIPAlias are the fixed
	// canonical key / alias the container-pinned entitlements entry
	// lands under in the normalized index. Both values are stable
	// so rego + deny-reason enrichment + activation scans all refer
	// to a single, well-known alias.
	EntitlementsPIPName  = "subject.entitledResources"
	EntitlementsPIPAlias = "entitledResources"

	// DefaultEntitlementsHTTPTimeout mirrors the default
	// AUTHZ_JWKS_HTTP_TIMEOUT value per D-AG-17 so the
	// entitlements knob block looks identical to the existing JWKS
	// block operators already know.
	DefaultEntitlementsHTTPTimeout = 5
	// DefaultEntitlementsHTTPRetries mirrors AUTHZ_JWKS_HTTP_RETRIES.
	DefaultEntitlementsHTTPRetries = 3
)

// D-AF-Y (2026-04-18) + ADR-0052: no PIP caching at any layer.
// `cacheable` / `cachePeriod` are deliberately absent from
// SimplifiedPIP; a simplified-PIP upload that carries those
// fields is rejected at validation time with HTTP 400.
type SimplifiedPIP struct {
	Name              string            `json:"name"`
	PipType           string            `json:"pipType,omitempty"`
	URL               string            `json:"url,omitempty"`
	HTTPMethod        string            `json:"httpMethod,omitempty"`
	Header            string            `json:"header,omitempty"`
	Claim             string            `json:"claim,omitempty"`
	BeanName          string            `json:"beanName,omitempty"`
	DefaultValue      any               `json:"defaultValue,omitempty"`
	Description       string            `json:"description,omitempty"`
	Domain            string            `json:"domain,omitempty"`
	RequestAttributes map[string]string `json:"requestAttributes,omitempty"`
	// Headers is polymorphic (ADR-0066 / O-6): the legacy `[]string` form is a
	// list of inbound header NAMES to forward from the request; the extended
	// `{name: value}` map form sets explicit values (values may carry `${...}`).
	// Kept as raw JSON so both shapes parse and round-trip; normalize.go lowers
	// it into ForwardHeaders + SetHeaders.
	Headers  json.RawMessage `json:"headers,omitempty"`
	Type     string          `json:"type,omitempty"`
	JsonPath string          `json:"jsonPath,omitempty"`

	// ── Extended request fields (ADR-0066). Values may carry `${...}`. ──
	Query map[string]string `json:"query,omitempty"`
	// Body is either a JSON object or a string (ADR-0066); kept raw so both
	// parse and round-trip. Runtime (pip.rego) expands `${...}` inside it.
	Body           json.RawMessage `json:"body,omitempty"`
	TimeoutSeconds *int            `json:"timeoutSeconds,omitempty"`
	Response       *ResponseSpec   `json:"response,omitempty"`
}

// ResponseSpec is the upload shape of the nested `response` block (ADR-0066 /
// ADR-0068). It supersedes the legacy flat `type` / `jsonPath` when present.
type ResponseSpec struct {
	// Type is accepted for backward-compat but IGNORED at runtime (v1 always
	// parses the body as JSON — ADR-0068).
	Type string `json:"type,omitempty"`
	// Extract is either a jsonPath STRING (alias = value) or a `{name: <spec>}`
	// MAP (alias = object; policies read subject.<alias>.<name>). A map entry's
	// <spec> is a jsonPath string or `{path, coerce, onMissing}`. Kept raw; Rego
	// branches on its JSON type at runtime.
	Extract   json.RawMessage `json:"extract,omitempty"`
	Coerce    string          `json:"coerce,omitempty"`
	OnMissing string          `json:"onMissing,omitempty"`
}

type NormalizedPIPs struct {
	ByName     map[string]NormalizedEntry `json:"byName"`
	AliasSet   map[string]bool            `json:"aliasSet,omitempty"`
	Local      LocalPIPs                  `json:"local"`
	Remote     RemotePIPs                 `json:"remote"`
	Activation ActivationIndexes          `json:"activation"`
}

type LocalPIPs struct {
	Token  map[string]TokenPIPConfig  `json:"token"`
	Header map[string]HeaderPIPConfig `json:"header"`
}

type RemotePIPs struct {
	General      map[string]GeneralPIPConfig `json:"general"`
	Entitlements *EntitlementsPIPConfig      `json:"entitlements,omitempty"`
}

// EntitlementsPIPConfig is the on-disk + on-wire shape of the single
// container-pinned entitlements-resolver entry. Rego reads this under
// `data.pips.remote.entitlements` to compose the V3 per-user URL and to
// read the per-call HTTP timeout/retries knobs at `http.send` time.
//
// Per ADR-0054 + D-AG-17 the set of knobs is intentionally small; no
// cache-related field ever appears on this struct (ADR-0052).
type EntitlementsPIPConfig struct {
	Name               string `json:"name"`
	Alias              string `json:"alias"`
	URL                string `json:"url"`
	HTTPTimeoutSeconds int    `json:"httpTimeoutSeconds"`
	HTTPRetries        int    `json:"httpRetries"`
}

// EntitlementsConfig is the in-memory representation the pap-client
// service holds for the container-pinned entitlements entry. It is built
// once at startup from AUTHZ_ENTITLEMENTS_URL + companions and merged
// into every normalized PIP document produced by the pull loop or mount watcher.
type EntitlementsConfig struct {
	URL                string
	HTTPTimeoutSeconds int
	HTTPRetries        int
}

// Entry returns the on-disk shape the normalized PIP document carries.
func (c *EntitlementsConfig) Entry() *EntitlementsPIPConfig {
	if c == nil || c.URL == "" {
		return nil
	}
	return &EntitlementsPIPConfig{
		Name:               EntitlementsPIPName,
		Alias:              EntitlementsPIPAlias,
		URL:                c.URL,
		HTTPTimeoutSeconds: c.HTTPTimeoutSeconds,
		HTTPRetries:        c.HTTPRetries,
	}
}

type ActivationIndexes struct {
	GeneralByResourceTypeOperation map[string]map[string][]string `json:"generalByResourceTypeOperation"`
}

type NormalizedEntry struct {
	Name    string `json:"name"`
	Alias   string `json:"alias"`
	PipType string `json:"pipType"`
}

type TokenPIPConfig struct {
	Name         string `json:"name"`
	Alias        string `json:"alias"`
	Claim        string `json:"claim"`
	DefaultValue any    `json:"defaultValue,omitempty"`
}

type HeaderPIPConfig struct {
	Name         string `json:"name"`
	Alias        string `json:"alias"`
	Header       string `json:"header"`
	DefaultValue any    `json:"defaultValue,omitempty"`
}

// GeneralPIPConfig is the normalized, Rego-consumed shape (data.pips.remote.general).
// Legacy and extended uploads both lower into this single representation
// (ADR-0066): legacy `url`/`httpMethod` are reused; legacy `requestAttributes`
// lowers into the wrapper Body; legacy `jsonPath`/`type` lower into Response.
type GeneralPIPConfig struct {
	Name       string            `json:"name"`
	Alias      string            `json:"alias"`
	URL        string            `json:"url"`
	HTTPMethod string            `json:"httpMethod"`
	Query      map[string]string `json:"query,omitempty"`
	// ForwardHeaders are inbound header NAMES to forward (legacy `[]string`).
	ForwardHeaders []string `json:"forwardHeaders,omitempty"`
	// SetHeaders are explicit name→value pairs (values may carry `${...}`).
	SetHeaders map[string]string `json:"setHeaders,omitempty"`
	// Body is the outgoing body (object or string) with `${...}` unexpanded;
	// nil when the call carries no body (e.g. GET). For legacy-shape PIPs it is
	// the wrapper `{id, filters:null, requestAttributes}` (nulls emitted).
	Body           json.RawMessage `json:"body,omitempty"`
	TimeoutSeconds int             `json:"timeoutSeconds"`
	Response       *ResponseConfig `json:"response,omitempty"`
	// DefaultValue is the soft-default the alias resolves to on an http error /
	// timeout / extract-miss under onMissing:defaultValue (ADR-0068). Carried
	// through so pip.rego's soft_default can read it; nil when unset.
	DefaultValue any `json:"defaultValue,omitempty"`
}

// ResponseConfig is the normalized `response` block. Extract stays raw (string
// or `{name: spec}` map) for Rego to branch on at runtime (ADR-0068).
type ResponseConfig struct {
	Extract   json.RawMessage `json:"extract,omitempty"`
	Coerce    string          `json:"coerce,omitempty"`
	OnMissing string          `json:"onMissing,omitempty"`
}

type RawPIPDocument struct {
	Version int             `json:"version"`
	Items   []SimplifiedPIP `json:"items"`
}

type PIPDocument struct {
	Raw        RawPIPDocument `json:"raw"`
	Normalized NormalizedPIPs `json:"normalized"`
}

type UploadSummary struct {
	Total   int `json:"total"`
	Token   int `json:"token"`
	Header  int `json:"header"`
	General int `json:"general"`
}
