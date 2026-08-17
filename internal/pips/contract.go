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

// Contract knobs for the extended GENERAL PIP request/response contract
// (authz-agent-ADR-0066/0067/0068). All substitution + extraction happens at
// runtime in Rego; this file only holds the upload-time validation helpers and
// the normalize-time legacy-wrapper builder.

const (
	// DefaultGeneralTimeoutSeconds is used when `timeoutSeconds` is omitted.
	DefaultGeneralTimeoutSeconds = 5
	// MinGeneralTimeoutSeconds / MaxGeneralTimeoutSeconds bound the per-call
	// timeout; out-of-range values are CLAMPED (never rejected) — ADR-0066.
	MinGeneralTimeoutSeconds = 1
	MaxGeneralTimeoutSeconds = 30

	// subjectIDTemplate is the literal placeholder written into the legacy
	// wrapper body's `id` at normalize time; Rego resolves it per-request.
	subjectIDTemplate = "${subject.id}"
)

// validCoerce is the closed set of `response.coerce` targets (ADR-0068),
// building on the typed extraction of ADR-0053.
var validCoerce = map[string]bool{
	"string": true, "number": true, "bool": true,
	"string[]": true, "number[]": true,
}

// validOnMissing is the closed set of `response.onMissing` modes (ADR-0068).
var validOnMissing = map[string]bool{
	"defaultValue": true, "empty": true, "error": true,
}

// clampTimeoutSeconds applies the ADR-0066 default + clamp policy.
func clampTimeoutSeconds(v *int) int {
	if v == nil {
		return DefaultGeneralTimeoutSeconds
	}
	switch {
	case *v < MinGeneralTimeoutSeconds:
		return MinGeneralTimeoutSeconds
	case *v > MaxGeneralTimeoutSeconds:
		return MaxGeneralTimeoutSeconds
	default:
		return *v
	}
}

// ── Placeholder (`${...}`) validation (ADR-0067) ─────────────────────────────
// A `${...}` may appear embedded in literal text; its inside must be
// `subject.<path>` or `resource.<path>` where <path> is the v1 jsonPath subset
// (dot / [n] / [*]). Malformed or unknown-scope placeholders fail the upload.

func validatePlaceholders(s string) error {
	i := 0
	for {
		rel := strings.Index(s[i:], "${")
		if rel < 0 {
			return nil
		}
		start := i + rel
		closeRel := strings.IndexByte(s[start+2:], '}')
		if closeRel < 0 {
			return fmt.Errorf("unterminated placeholder ${...} in %q", s)
		}
		end := start + 2 + closeRel
		inner := s[start+2 : end]
		if err := validatePlaceholderInner(inner); err != nil {
			return err
		}
		i = end + 1
	}
}

func validatePlaceholderInner(inner string) error {
	if inner == "" {
		return fmt.Errorf("empty placeholder ${}")
	}
	var rest string
	switch {
	case strings.HasPrefix(inner, "subject."):
		rest = inner[len("subject."):]
	case strings.HasPrefix(inner, "resource."):
		rest = inner[len("resource."):]
	default:
		return fmt.Errorf("unsupported placeholder scope in ${%s} (only subject.* / resource.*)", inner)
	}
	if rest == "" {
		return fmt.Errorf("placeholder ${%s} has empty path", inner)
	}
	if err := validatePath(rest, false); err != nil {
		return fmt.Errorf("placeholder ${%s}: %w", inner, err)
	}
	return nil
}

// validateJSONPathString validates an absolute `response.extract` / legacy
// `jsonPath` expression against the v1 subset ($, dot, [n], [*]); recursive
// descent ($..) and filters ([?(…)]) are rejected (ADR-0067/0068 / O-4).
func validateJSONPathString(expr string) error {
	if strings.TrimSpace(expr) == "" {
		return fmt.Errorf("empty jsonPath")
	}
	return validatePath(expr, true)
}

// validatePath walks the v1 jsonPath grammar. absolute=true requires a leading
// `$` (extract form); absolute=false is the relative form used after a
// subject./resource. placeholder scope.
func validatePath(path string, absolute bool) error {
	n := len(path)
	i := 0
	if absolute {
		if n == 0 || path[0] != '$' {
			return fmt.Errorf("jsonPath must start with '$' (got %q)", path)
		}
		i = 1
	} else {
		// first segment is a bare field name
		j := i
		for j < n && path[j] != '.' && path[j] != '[' {
			j++
		}
		if err := checkField(path[i:j]); err != nil {
			return err
		}
		i = j
	}
	for i < n {
		switch path[i] {
		case '.':
			i++
			j := i
			for j < n && path[j] != '.' && path[j] != '[' {
				j++
			}
			field := path[i:j]
			if field == "" {
				return fmt.Errorf("empty path segment in %q (recursive descent '..' is not supported)", path)
			}
			if err := checkField(field); err != nil {
				return err
			}
			i = j
		case '[':
			closeRel := strings.IndexByte(path[i:], ']')
			if closeRel < 0 {
				return fmt.Errorf("unclosed '[' in %q", path)
			}
			inner := path[i+1 : i+closeRel]
			if inner != "*" && !isAllDigits(inner) {
				return fmt.Errorf("unsupported bracket [%s] in %q (only [n] and [*]; filters/recursive-descent are deferred)", inner, path)
			}
			i = i + closeRel + 1
		default:
			return fmt.Errorf("unexpected token at %q in %q", path[i:], path)
		}
	}
	return nil
}

func checkField(field string) error {
	if field == "" {
		return fmt.Errorf("empty field name")
	}
	if strings.ContainsAny(field, "$*?[]") {
		return fmt.Errorf("invalid field name %q", field)
	}
	return nil
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// isAbsentRaw reports whether a raw JSON value is missing or literal `null` —
// treated as "not provided" (a JSON null must not silently deserialize into a
// zero value and slip past validation).
func isAbsentRaw(raw json.RawMessage) bool {
	t := bytes.TrimSpace(raw)
	return len(t) == 0 || string(t) == "null"
}

// walkJSONStrings applies fn to every string leaf inside a parsed JSON value.
func walkJSONStrings(v any, fn func(string) error) error {
	switch t := v.(type) {
	case string:
		return fn(t)
	case map[string]any:
		for _, val := range t {
			if err := walkJSONStrings(val, fn); err != nil {
				return err
			}
		}
	case []any:
		for _, val := range t {
			if err := walkJSONStrings(val, fn); err != nil {
				return err
			}
		}
	}
	return nil
}

// validatePlaceholdersInRawJSON validates `${...}` inside every string leaf of a
// raw JSON value (object or string body, map values, etc.).
func validatePlaceholdersInRawJSON(raw json.RawMessage) error {
	if len(raw) == 0 {
		return nil
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
	return walkJSONStrings(v, validatePlaceholders)
}

// ── Header form detection (ADR-0066 / O-6) ───────────────────────────────────

// parseHeaders lowers the polymorphic upload `headers` into the normalized
// ForwardHeaders ([]string, legacy) + SetHeaders (map, extended) split. Exactly
// one form is accepted per upload. Absent or JSON `null` → no headers; a scalar
// (number/string/bool) is rejected. The shape is inspected by first byte so a
// JSON null cannot silently deserialize into a nil slice and slip past.
func parseHeaders(raw json.RawMessage) (forward []string, set map[string]string, err error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || string(trimmed) == "null" {
		return nil, nil, nil
	}
	switch trimmed[0] {
	case '[':
		var asList []string
		if e := json.Unmarshal(trimmed, &asList); e != nil {
			return nil, nil, fmt.Errorf("headers list must be an array of inbound header names: %w", e)
		}
		if len(asList) == 0 {
			return nil, nil, nil
		}
		return asList, nil, nil
	case '{':
		var asMap map[string]string
		if e := json.Unmarshal(trimmed, &asMap); e != nil {
			return nil, nil, fmt.Errorf("headers map must be a {name: value} object of strings: %w", e)
		}
		if len(asMap) == 0 {
			return nil, nil, nil
		}
		return nil, asMap, nil
	default:
		return nil, nil, fmt.Errorf("headers must be a []string (inbound names to forward) or a {name: value} map")
	}
}

// ── Legacy wrapper body builder (ADR-0066 / verified access-control shape) ────

// legacyRequestBody mirrors access-control's PipRequestBody: a top-level object
// {id, filters, requestAttributes} where `id` is a sibling of
// `requestAttributes`, `filters` is null for GENERAL, and null fields are
// EMITTED (byte-parity invariant NEW-4). Field order matches the Java
// declaration order (id, filters, requestAttributes).
type legacyRequestBody struct {
	ID                string            `json:"id"`
	Filters           any               `json:"filters"`
	RequestAttributes map[string]string `json:"requestAttributes"`
}

// buildLegacyWrapperBody produces the wrapper legacy sends for a POST GENERAL
// PIP: {"id":"${subject.id}","filters":null,"requestAttributes":<attrs|null>}.
// Empty/absent attrs marshal to `requestAttributes: null` (nil map → null).
func buildLegacyWrapperBody(attrs map[string]string) (json.RawMessage, error) {
	body := legacyRequestBody{
		ID:      subjectIDTemplate,
		Filters: nil,
	}
	if len(attrs) > 0 {
		body.RequestAttributes = attrs
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshal legacy wrapper body: %w", err)
	}
	return raw, nil
}
