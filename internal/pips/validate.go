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

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

// Parse unmarshals a simplified-PIP upload payload. Per ADR-0052 any
// `cacheable` / `cachePeriod` JSON fields the payload may carry are
// silently dropped — `SimplifiedPIP` does not declare them, and Go's
// default unmarshal ignores unknown fields, so the runtime normalized
// config is unaffected by the presence of legacy-compat caching metadata
// on incoming payloads. This lets upload clients send the same
// simplified-PIP JSON to both Authz Agent and legacy `access-control`
// without maintaining two fixture variants.
func Parse(input []byte) ([]SimplifiedPIP, error) {
	raw := strings.TrimSpace(string(input))
	if raw == "" {
		return nil, fmt.Errorf("empty payload")
	}

	if strings.HasPrefix(raw, "[") {
		var items []SimplifiedPIP
		if err := json.Unmarshal(input, &items); err != nil {
			return nil, fmt.Errorf("invalid json: %w", err)
		}
		return items, nil
	}

	var wrapper struct {
		PIPs []SimplifiedPIP `json:"pips"`
	}
	if err := json.Unmarshal(input, &wrapper); err != nil {
		return nil, fmt.Errorf("invalid json: %w", err)
	}
	if len(wrapper.PIPs) > 0 {
		return wrapper.PIPs, nil
	}

	return nil, fmt.Errorf("payload must be a PIP array or object with pips[]")
}

func Validate(items []SimplifiedPIP) error {
	names := make(map[string]int, len(items))

	for idx, item := range items {
		if err := validateSingle(idx, item); err != nil {
			return err
		}

		if prev, dup := names[item.Name]; dup {
			return fmt.Errorf("pip %d: duplicate name %q (first seen at %d)", idx, item.Name, prev)
		}
		names[item.Name] = idx
	}

	return nil
}

func validateSingle(idx int, pip SimplifiedPIP) error {
	name := strings.TrimSpace(pip.Name)
	if name == "" {
		return fmt.Errorf("pip %d: name is required", idx)
	}

	if !strings.HasPrefix(name, "subject.") {
		return fmt.Errorf("pip %d: name must start with 'subject.' (got %q)", idx, name)
	}

	alias := name[len("subject."):]
	if alias == "" {
		return fmt.Errorf("pip %d: name must have alias after 'subject.' (got %q)", idx, name)
	}

	pipType := resolvePipType(pip)

	if err := rejectUnsupported(idx, pipType, pip); err != nil {
		return err
	}

	switch pipType {
	case PipTypeToken:
		return validateTokenPIP(idx, pip)
	case PipTypeHeader:
		return validateHeaderPIP(idx, pip)
	case PipTypeGeneral:
		return validateGeneralPIP(idx, pip)
	default:
		return fmt.Errorf("pip %d: unsupported pipType %q", idx, pipType)
	}
}

func rejectUnsupported(idx int, pipType string, pip SimplifiedPIP) error {
	switch pipType {
	case PipTypeFiltered:
		return fmt.Errorf("pip %d (%s): unsupported pipType FILTERED", idx, pip.Name)
	case PipTypePermissionScope:
		return fmt.Errorf("pip %d (%s): unsupported pipType PERMISSION_SCOPE", idx, pip.Name)
	case PipTypeMapping:
		return fmt.Errorf("pip %d (%s): unsupported pipType MAPPING", idx, pip.Name)
	case PipTypeEntitlements:
		// D-AG-16 / ADR-0054: ENTITLEMENT is container-pinned and is
		// materialised at startup from AUTHZ_ENTITLEMENTS_URL + companions.
		// It cannot be delivered via the pull loop or a ConfigMap mount;
		// the error message names the runtime knob so the operator knows
		// what to set without having to read the ADR.
		return fmt.Errorf(
			`pip %d (%s): pipType "ENTITLEMENT" is container-pinned; configure AUTHZ_ENTITLEMENTS_URL on the pap-client container instead`,
			idx, pip.Name,
		)
	}

	if pipType == PipTypeGeneral && strings.TrimSpace(pip.BeanName) != "" {
		return fmt.Errorf("pip %d (%s): unsupported GENERAL pip with beanName", idx, pip.Name)
	}

	return nil
}

func validateTokenPIP(idx int, pip SimplifiedPIP) error {
	if strings.TrimSpace(pip.Claim) == "" {
		return fmt.Errorf("pip %d (%s): TOKEN pip requires 'claim' field", idx, pip.Name)
	}
	return nil
}

func validateHeaderPIP(idx int, pip SimplifiedPIP) error {
	if strings.TrimSpace(pip.Header) == "" {
		return fmt.Errorf("pip %d (%s): HEADER pip requires 'header' field", idx, pip.Name)
	}
	return nil
}

func validateGeneralPIP(idx int, pip SimplifiedPIP) error {
	if strings.TrimSpace(pip.URL) == "" {
		return fmt.Errorf("pip %d (%s): GENERAL pip requires 'url' field", idx, pip.Name)
	}

	method := strings.ToUpper(strings.TrimSpace(pip.HTTPMethod))
	if method != "" && method != "GET" && method != "POST" {
		return fmt.Errorf("pip %d (%s): httpMethod must be GET or POST (got %q)", idx, pip.Name, pip.HTTPMethod)
	}

	// ADR-0066: a url query-string and a separate `query` object are mutually
	// exclusive.
	if strings.Contains(pip.URL, "?") && len(pip.Query) > 0 {
		return fmt.Errorf("pip %d (%s): url carries a query-string and a separate 'query' object is set — use one or the other", idx, pip.Name)
	}

	// ADR-0066: GET never carries a body (legacy sends a body only on POST).
	if method == "GET" && len(pip.Body) > 0 {
		return fmt.Errorf("pip %d (%s): httpMethod GET with a 'body' is not allowed (choose POST or drop the body)", idx, pip.Name)
	}

	// O-6: headers is either a []string (forward inbound names) or a {name:value} map.
	if _, _, err := parseHeaders(pip.Headers); err != nil {
		return fmt.Errorf("pip %d (%s): %w", idx, pip.Name, err)
	}

	// ADR-0067: validate the `${...}` placeholder set (scope + syntax) across
	// every substitutable value. Substitution itself is runtime (Rego).
	if err := validateGeneralPlaceholders(pip); err != nil {
		return fmt.Errorf("pip %d (%s): %w", idx, pip.Name, err)
	}

	// ADR-0066/0068: `response` supersedes legacy `type`/`jsonPath` when present.
	if pip.Response != nil {
		return validateResponseSpec(idx, pip)
	}

	// Legacy response path (response absent): keep the existing type/jsonPath
	// coupling, then validate the jsonPath against the v1 subset.
	jsonPath := strings.TrimSpace(pip.JsonPath)
	if strings.TrimSpace(pip.PipType) != "" {
		payloadType := strings.ToUpper(strings.TrimSpace(pip.Type))
		if payloadType != "" && payloadType != "JSON" && payloadType != "TEXT" {
			return fmt.Errorf("pip %d (%s): type must be JSON or TEXT (got %q)", idx, pip.Name, pip.Type)
		}
		if jsonPath != "" && payloadType != "JSON" {
			return fmt.Errorf("pip %d (%s): jsonPath requires type=JSON (got type=%q)", idx, pip.Name, pip.Type)
		}
	} else if jsonPath != "" {
		return fmt.Errorf("pip %d (%s): jsonPath requires pipType=GENERAL + type=JSON", idx, pip.Name)
	}
	if jsonPath != "" {
		if err := validateJSONPathString(jsonPath); err != nil {
			return fmt.Errorf("pip %d (%s): jsonPath %w", idx, pip.Name, err)
		}
	}

	return nil
}

// validateGeneralPlaceholders checks `${...}` syntax + scope in url, query
// values, explicit header values, requestAttributes values, and the body.
func validateGeneralPlaceholders(pip SimplifiedPIP) error {
	if err := validatePlaceholders(pip.URL); err != nil {
		return fmt.Errorf("url %w", err)
	}
	for k, v := range pip.Query {
		if err := validatePlaceholders(v); err != nil {
			return fmt.Errorf("query[%s] %w", k, err)
		}
	}
	if _, set, _ := parseHeaders(pip.Headers); set != nil {
		for k, v := range set {
			if err := validatePlaceholders(v); err != nil {
				return fmt.Errorf("headers[%s] %w", k, err)
			}
		}
	}
	for k, v := range pip.RequestAttributes {
		if err := validatePlaceholders(v); err != nil {
			return fmt.Errorf("requestAttributes[%s] %w", k, err)
		}
	}
	if len(pip.Body) > 0 {
		if err := validatePlaceholdersInRawJSON(pip.Body); err != nil {
			return fmt.Errorf("body %w", err)
		}
	}
	return nil
}

// validateResponseSpec validates the nested `response` block: extract (jsonPath
// string or {name: spec} map), coerce, and onMissing (ADR-0068).
func validateResponseSpec(idx int, pip SimplifiedPIP) error {
	r := pip.Response
	if r.Coerce != "" && !validCoerce[r.Coerce] {
		return fmt.Errorf("pip %d (%s): response.coerce %q must be one of string|number|bool|string[]|number[]", idx, pip.Name, r.Coerce)
	}
	if r.OnMissing != "" && !validOnMissing[r.OnMissing] {
		return fmt.Errorf("pip %d (%s): response.onMissing %q must be one of defaultValue|empty|error", idx, pip.Name, r.OnMissing)
	}
	// onMissing:defaultValue with no (or null) defaultValue silently degrades to a
	// fail-closed miss at runtime (soft_default requires a non-null default); reject
	// it at upload so the misconfiguration is explicit rather than silent.
	if r.OnMissing == "defaultValue" && pip.DefaultValue == nil {
		return fmt.Errorf("pip %d (%s): response.onMissing \"defaultValue\" requires a non-null defaultValue", idx, pip.Name)
	}
	// Absent / null extract → no post-processing (alias = whole body).
	if isAbsentRaw(r.Extract) {
		return nil
	}

	trimmed := bytes.TrimSpace(r.Extract)
	switch trimmed[0] {
	case '"':
		var asStr string
		if err := json.Unmarshal(trimmed, &asStr); err != nil {
			return fmt.Errorf("pip %d (%s): response.extract is not a valid string: %w", idx, pip.Name, err)
		}
		if err := validateJSONPathString(asStr); err != nil {
			return fmt.Errorf("pip %d (%s): response.extract %w", idx, pip.Name, err)
		}
		return nil
	case '{':
		var asMap map[string]json.RawMessage
		if err := json.Unmarshal(trimmed, &asMap); err != nil {
			return fmt.Errorf("pip %d (%s): response.extract map is invalid: %w", idx, pip.Name, err)
		}
		if len(asMap) == 0 {
			return fmt.Errorf("pip %d (%s): response.extract map must have at least one entry", idx, pip.Name)
		}
		for name, spec := range asMap {
			if err := validateExtractEntry(spec); err != nil {
				return fmt.Errorf("pip %d (%s): response.extract[%s] %w", idx, pip.Name, name, err)
			}
		}
		return nil
	default:
		return fmt.Errorf("pip %d (%s): response.extract must be a jsonPath string or a {name: spec} map", idx, pip.Name)
	}
}

// validateExtractEntry validates one map-form extract entry: a jsonPath string
// or a {path, coerce, onMissing} object (per-entry coerce/onMissing fall back to
// block-level at runtime).
func validateExtractEntry(spec json.RawMessage) error {
	trimmed := bytes.TrimSpace(spec)
	if len(trimmed) == 0 || string(trimmed) == "null" {
		return fmt.Errorf("map entry must not be null")
	}

	switch trimmed[0] {
	case '"':
		var asStr string
		if err := json.Unmarshal(trimmed, &asStr); err != nil {
			return fmt.Errorf("invalid string entry: %w", err)
		}
		return validateJSONPathString(asStr)
	case '{':
		var obj struct {
			Path      string `json:"path"`
			Coerce    string `json:"coerce"`
			OnMissing string `json:"onMissing"`
		}
		dec := json.NewDecoder(bytes.NewReader(trimmed))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&obj); err != nil {
			return fmt.Errorf("invalid entry object: %w", err)
		}
		if strings.TrimSpace(obj.Path) == "" {
			return fmt.Errorf("map entry requires 'path'")
		}
		if err := validateJSONPathString(obj.Path); err != nil {
			return err
		}
		if obj.Coerce != "" && !validCoerce[obj.Coerce] {
			return fmt.Errorf("coerce %q must be one of string|number|bool|string[]|number[]", obj.Coerce)
		}
		if obj.OnMissing != "" && !validOnMissing[obj.OnMissing] {
			return fmt.Errorf("onMissing %q must be one of defaultValue|empty|error", obj.OnMissing)
		}
		return nil
	default:
		return fmt.Errorf("map entry must be a jsonPath string or a {path,coerce,onMissing} object")
	}
}

func resolvePipType(pip SimplifiedPIP) string {
	explicit := strings.ToUpper(strings.TrimSpace(pip.PipType))
	if explicit != "" {
		return explicit
	}

	legacyType := strings.ToUpper(strings.TrimSpace(pip.Type))
	if legacyType != "" {
		return legacyType
	}

	if strings.TrimSpace(pip.Claim) != "" {
		return PipTypeToken
	}
	if strings.TrimSpace(pip.Header) != "" {
		return PipTypeHeader
	}

	return PipTypeGeneral
}
