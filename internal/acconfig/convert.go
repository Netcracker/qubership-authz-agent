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

package acconfig

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"regexp"
	"strconv"
	"strings"

	"authz-agent/internal/pips"
	"authz-agent/internal/simplifiedpolicies"
)

// Target pattern regexes. The access-control export rewrites targets through
// PolicySetExportExpressionConverter before serving them, so the patterns here
// reflect the post-rewrite wire format.
var (
	// resourceTypePattern matches targets of the form:
	//   resourceType == 'X'  or  resourceType EQUALS 'X'
	resourceTypePattern = regexp.MustCompile(`(?i)^resourceType\s+(?:==|EQUALS)\s+'([^']+)'$`)

	// operationPattern matches targets of the form:
	//   operation == 'X'  or  operation EQUALS 'X'
	operationPattern = regexp.MustCompile(`(?i)^operation\s+(?:==|EQUALS)\s+'([^']+)'$`)
)

// Stats reports what one conversion had to drop.
//
// It exists because a converter that skips every rule produces an empty policy
// list, and an empty policy list is indistinguishable from a healthy
// installation that happens to have no simplified policies. That is exactly how
// the target-level mismatch below survived behind a Ready Pod and a
// policiesLoaded=true status file: every decision came back DENY while nothing
// reported a problem. The counts are written to the pull status file and served
// on /health so the condition is visible without reading the log stream.
type Stats struct {
	// PolicySets counts SIMPLIFIED policy sets seen (DEFAULT ones are skipped
	// before this package looks at them and are not counted).
	PolicySets        int `json:"policySets"`
	PolicySetsSkipped int `json:"policySetsSkipped"`
	// Rules counts rules inside SIMPLIFIED policy sets that were reached, i.e.
	// excluding those in a policy set dropped for an unparseable target.
	Rules        int `json:"rules"`
	RulesSkipped int `json:"rulesSkipped"`
	// RulesDenySkipped counts DENY rules, which have no equivalent in the
	// simplified model. Normal data, kept separate from RulesSkipped so the
	// latter only ever means "could not be converted".
	RulesDenySkipped int `json:"rulesDenySkipped"`
	// Policies counts the simplified policies produced.
	Policies int `json:"policies"`
}

// ConvertPolicySets parses a raw V3PolicySetsResponse JSON body and converts
// all SIMPLIFIED policy sets into simplified policies. DEFAULT policy sets (and
// those with an absent "type" key) are silently skipped. A policy set with an
// unparseable target is logged loudly and its policies are dropped entirely; a
// rule whose targets cannot be mapped to an operation and a role set is logged
// and skipped. The returned Stats carry the skip counts.
func ConvertPolicySets(raw []byte, logger *log.Logger) ([]simplifiedpolicies.Policy, Stats, error) {
	var resp V3PolicySetsResponse
	var stats Stats
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, stats, fmt.Errorf("acconfig: parse policy-sets response: %w", err)
	}
	policies := convertPolicySets(resp.PolicySets, logger, &stats)
	stats.Policies = len(policies)
	return policies, stats, nil
}

// ConvertPIPs parses a raw V3PIPsResponse JSON body and converts the PIP list
// to a slice of pips.SimplifiedPIP, silently skipping types that the agent does
// not handle (FILTERED, PERMISSION_SCOPE, MAPPING, and GENERAL with beanName).
func ConvertPIPs(raw []byte, logger *log.Logger) ([]pips.SimplifiedPIP, error) {
	var resp V3PIPsResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, fmt.Errorf("acconfig: parse pips response: %w", err)
	}
	return convertPIPs(resp.PIPs, logger), nil
}

// convertPolicySets iterates the policy-set list and dispatches SIMPLIFIED ones.
func convertPolicySets(sets []PolicySetV3, logger *log.Logger, stats *Stats) []simplifiedpolicies.Policy {
	var result []simplifiedpolicies.Policy
	for _, ps := range sets {
		if ps.Type != "SIMPLIFIED" {
			// DEFAULT policy sets are normal data, not a defect; no log line.
			continue
		}
		result = append(result, convertPolicySet(ps, logger, stats)...)
	}
	return result
}

// convertPolicySet converts one SIMPLIFIED policy set into zero or more
// simplified policies. If the policy-set target is unparseable, all derived
// policies are dropped and the problem is logged.
func convertPolicySet(ps PolicySetV3, logger *log.Logger, stats *Stats) []simplifiedpolicies.Policy {
	stats.PolicySets++

	var resourceType string
	switch t := parseTarget(ps.Target); t.kind {
	case targetResourceType:
		resourceType = t.value
	case targetAny:
		resourceType = "ALL"
	default:
		stats.PolicySetsSkipped++
		logger.Printf("warn: acconfig: policy set %q (id=%s): unparseable target %q — all derived policies skipped",
			ps.Name, ps.PolicySetID, ps.Target)
		return nil
	}

	component := ps.Domain
	if component == "" {
		// Domain is not always set for SIMPLIFIED policy sets that pre-date the
		// field; fall back to the tenant ID which is always present.
		component = ps.TenantID
	}
	if component == "" {
		component = "default"
	}

	var result []simplifiedpolicies.Policy
	for _, policy := range ps.Policies {
		policyTarget := parseTarget(policy.Target)
		for _, rule := range policy.Rules {
			stats.Rules++
			if rule.Effect == "DENY" {
				// DENY rules have no equivalent in the simplified model; skip.
				stats.RulesDenySkipped++
				continue
			}
			operation, roles, ok := resolveOperationAndRoles(policyTarget, parseTarget(rule.Target))
			if !ok {
				stats.RulesSkipped++
				logger.Printf("warn: acconfig: policy set %q, rule %q: policy target %q and rule target %q do not yield an operation and a role set — rule skipped",
					ps.Name, rule.RuleID, policy.Target, rule.Target)
				continue
			}

			sp := simplifiedpolicies.Policy{
				Component:    component,
				ResourceType: resourceType,
				Operation:    operation,
				Roles:        rolesToAny(roles),
			}

			// Condition: null (absent) ⇒ no condition field (equivalent to "true").
			if rule.Condition != nil && strings.TrimSpace(*rule.Condition) != "" {
				sp.Condition = *rule.Condition
			}

			if strings.TrimSpace(rule.RSQLPredicate) != "" {
				sp.RSQLPredicate = rule.RSQLPredicate
			}
			if strings.TrimSpace(rule.SQLPredicate) != "" {
				sp.SQLPredicate = rule.SQLPredicate
			}
			if strings.TrimSpace(rule.MongoDBPredicate) != "" {
				sp.MongoDBPredicate = rule.MongoDBPredicate
			}
			if strings.TrimSpace(rule.QueryDSLPredicate) != "" {
				sp.QueryDSLPredicate = rule.QueryDSLPredicate
			}

			result = append(result, sp)
		}
	}
	return result
}

// targetKind classifies a v3 target expression by what it constrains.
//
// access-control does not guarantee which nesting level carries which
// predicate. The export served by the installation on
// cloud-platform-security-dev-4 puts the operation on the policy and the roles
// on the rule; the shape this package was originally written against — and the
// pre-2026-08 fixtures — puts them the other way round. Classifying by content
// and then resolving the pair (see resolveOperationAndRoles) converts both
// without having to know which access-control version produced the payload.
type targetKind int

const (
	targetUnknown targetKind = iota
	// targetAny is "true" or an empty string: no restriction at this level.
	targetAny
	targetResourceType
	targetOperation
	targetRoles
)

// parsedTarget is the result of classifying one target expression.
type parsedTarget struct {
	kind  targetKind
	value string   // resource type or operation literal
	roles []string // targetRoles only
}

// parseTarget classifies a target expression by its content.
func parseTarget(target string) parsedTarget {
	t := strings.TrimSpace(target)
	if t == "" || strings.EqualFold(t, "true") {
		return parsedTarget{kind: targetAny}
	}
	if m := resourceTypePattern.FindStringSubmatch(t); len(m) == 2 {
		return parsedTarget{kind: targetResourceType, value: m[1]}
	}
	if m := operationPattern.FindStringSubmatch(t); len(m) == 2 {
		return parsedTarget{kind: targetOperation, value: m[1]}
	}
	if roles, ok := parseRoleExpression(t); ok {
		return parsedTarget{kind: targetRoles, roles: roles}
	}
	return parsedTarget{kind: targetUnknown}
}

// resolveOperationAndRoles maps a (policy target, rule target) pair to one
// operation and one role set, whichever level each predicate arrived on.
//
// The table is exhaustive rather than permissive on purpose. A pair that is not
// listed cannot be read unambiguously, and an unreadable role restriction must
// drop the rule rather than produce a policy with no roles — which the OPA
// model reads as "open to everyone". Until 2026-08-01 an unrecognised role
// target did exactly that, silently.
func resolveOperationAndRoles(policy, rule parsedTarget) (operation string, roles []string, ok bool) {
	switch {
	// Shape served by access-control: operation on the policy, roles on the rule.
	case policy.kind == targetOperation && rule.kind == targetRoles:
		return policy.value, rule.roles, true
	case policy.kind == targetOperation && rule.kind == targetAny:
		return policy.value, nil, true

	// Shape the pre-2026-08 fixtures use: roles on the policy, operation on the rule.
	case policy.kind == targetRoles && rule.kind == targetOperation:
		return rule.value, policy.roles, true
	case policy.kind == targetAny && rule.kind == targetOperation:
		return rule.value, nil, true

	// No operation restriction at either level ⇒ all operations.
	case policy.kind == targetRoles && rule.kind == targetAny:
		return "ALL", policy.roles, true
	case policy.kind == targetAny && rule.kind == targetRoles:
		return "ALL", rule.roles, true
	case policy.kind == targetAny && rule.kind == targetAny:
		return "ALL", nil, true
	}

	// Everything else — an unknown expression at either level, a resourceType
	// nested below the policy set, or the same predicate on both levels.
	return "", nil, false
}

// parseRoleExpression parses the role grammar that
// PolicySetExportExpressionConverter emits:
//
//	expr     := clause ( "OR" clause )*
//	clause   := "subject.roles" ( "CONTAINS" | "CONTAINS ANY" ) operands
//	operands := "'" role "'" ( "," "'" role "'" )*
//
// Both operators mean "the subject holds at least one of the listed roles", and
// OR unions the clauses, so the whole expression flattens to a single role set
// — which is exactly the semantics of simplifiedpolicies.Policy.Roles. Access
// control emits CONTAINS ANY even for a single-role simplified upload, and
// emits multi-value operands for a multi-role one; both were observed on
// dev-4 alongside OR-chains that mix the two operators.
//
// The scan is a token walk rather than a split on " OR " because role literals
// are opaque strings: a role named "A OR B" would break a naive split.
//
// Returns (roles, true) only on a full match. Callers must treat false as
// "cannot convert", never as "no role restriction".
//
// Note that "subject.roles CONTAINS 'ROLE_M2M'" is how the export represents
// allowM2MAccess=true in the original simplified upload. At the OPA level
// ROLE_M2M is just another role, so no special case is needed.
func parseRoleExpression(expr string) ([]string, bool) {
	s := &scanner{in: expr}
	var roles []string
	seen := make(map[string]struct{})

	for {
		if !s.acceptWord("subject.roles") || !s.acceptWord("CONTAINS") {
			return nil, false
		}
		// "ANY" is optional: CONTAINS and CONTAINS ANY are both unions here.
		s.acceptWord("ANY")

		for {
			role, ok := s.acceptQuoted()
			if !ok {
				return nil, false
			}
			if _, dup := seen[role]; !dup {
				seen[role] = struct{}{}
				roles = append(roles, role)
			}
			if !s.acceptByte(',') {
				break
			}
		}

		if s.atEnd() {
			return roles, len(roles) > 0
		}
		if !s.acceptWord("OR") {
			return nil, false
		}
	}
}

// scanner is a minimal cursor over a target expression.
type scanner struct {
	in  string
	pos int
}

func (s *scanner) skipSpace() {
	for s.pos < len(s.in) {
		switch s.in[s.pos] {
		case ' ', '\t', '\n', '\r':
			s.pos++
		default:
			return
		}
	}
}

func (s *scanner) atEnd() bool {
	s.skipSpace()
	return s.pos >= len(s.in)
}

// acceptWord consumes word case-insensitively when it is the next token. The
// delimiter check keeps "CONTAINS" from matching the prefix of "CONTAINSFOO".
func (s *scanner) acceptWord(word string) bool {
	s.skipSpace()
	end := s.pos + len(word)
	if end > len(s.in) || !strings.EqualFold(s.in[s.pos:end], word) {
		return false
	}
	if end < len(s.in) {
		switch s.in[end] {
		case ' ', '\t', '\n', '\r', '\'', ',':
		default:
			return false
		}
	}
	s.pos = end
	return true
}

func (s *scanner) acceptByte(b byte) bool {
	s.skipSpace()
	if s.pos < len(s.in) && s.in[s.pos] == b {
		s.pos++
		return true
	}
	return false
}

// acceptQuoted consumes a single-quoted literal. The export has no escape
// syntax — a role name containing a quote cannot be expressed — so the first
// closing quote ends the literal.
func (s *scanner) acceptQuoted() (string, bool) {
	s.skipSpace()
	if s.pos >= len(s.in) || s.in[s.pos] != '\'' {
		return "", false
	}
	rel := strings.IndexByte(s.in[s.pos+1:], '\'')
	if rel < 0 {
		return "", false
	}
	lit := s.in[s.pos+1 : s.pos+1+rel]
	s.pos += rel + 2
	if strings.TrimSpace(lit) == "" {
		return "", false
	}
	return lit, true
}

func rolesToAny(roles []string) []any {
	out := make([]any, len(roles))
	for i, r := range roles {
		out[i] = r
	}
	return out
}

// convertPIPs converts the v3 PIP list, filtering out types the agent does not
// support. Filtering is silent for the same reason DEFAULT policy sets are
// silent: these types are normal data in access-control.
func convertPIPs(v3pips []PIPV3, _ *log.Logger) []pips.SimplifiedPIP {
	result := make([]pips.SimplifiedPIP, 0, len(v3pips))
	for _, p := range v3pips {
		sp, ok := convertPIP(p)
		if !ok {
			continue
		}
		result = append(result, sp)
	}
	return result
}

// convertPIP converts one PIPV3 to a pips.SimplifiedPIP. Returns (zero, false)
// when the PIP type is not supported by the agent.
func convertPIP(p PIPV3) (pips.SimplifiedPIP, bool) {
	switch p.PipType {
	case pips.PipTypeFiltered,
		pips.PipTypePermissionScope,
		pips.PipTypeMapping,
		// ENTITLEMENT is container-pinned via AUTHZ_ENTITLEMENTS_URL; it must
		// never appear in the policy-pull data path (D-AG-16 / ADR-0054).
		pips.PipTypeEntitlements:
		return pips.SimplifiedPIP{}, false
	case pips.PipTypeGeneral:
		// GENERAL with beanName is not supported (no HTTP call, framework-specific).
		if p.BeanName != "" {
			return pips.SimplifiedPIP{}, false
		}
	}

	sp := pips.SimplifiedPIP{
		Name:              p.Name,
		PipType:           p.PipType,
		URL:               p.URL,
		HTTPMethod:        p.HTTPMethod,
		Header:            p.Header,
		Claim:             p.Claim,
		BeanName:          p.BeanName,
		Domain:            coalesce(p.Domain, p.TenantID),
		Type:              p.Type,
		JsonPath:          p.JsonPath,
		RequestAttributes: stringifyRequestAttributes(p.RequestAttributes),
	}

	if len(p.DefaultValue) > 0 {
		sp.DefaultValue = json.RawMessage(p.DefaultValue)
	}

	// Convert the headers field. The v3 export may carry headers as a
	// comma-separated string ("A,B,C") that is not valid JSON. Normalise it to a
	// JSON array so pips.NormalizeItems can parse it.
	sp.Headers = normaliseHeaders(p.Headers)

	// PDP contract extension (ADR-0066..0069). Absent from access-control's own
	// model, so on a real source these stay nil and the PIP behaves exactly as
	// before; the authz-policy-admin does carry them. `response` is decoded rather than
	// passed through because pips.SimplifiedPIP holds it as a typed
	// *ResponseSpec — a malformed block is dropped rather than failing the whole
	// pull, on the same fail-soft principle as the rest of this converter: one
	// bad PIP must not cost the agent every other policy in the payload.
	sp.Query = p.Query
	sp.Body = p.Body
	sp.TimeoutSeconds = p.TimeoutSeconds
	if len(bytes.TrimSpace(p.Response)) > 0 {
		var spec pips.ResponseSpec
		if err := json.Unmarshal(p.Response, &spec); err == nil {
			sp.Response = &spec
		}
	}

	return sp, true
}

// normaliseHeaders converts the v3 headers field to a JSON-array form that
// pips.NormalizeItems understands. The v3 format uses either:
//   - a JSON array:  ["A", "B"]
//   - a JSON object: {"X-My-Header": "value"}
//   - a comma-separated string: "A,B,C"  (legacy access-control serialisation)
//
// The first two are passed through unchanged; the string form is split and
// re-encoded as a JSON array.
func normaliseHeaders(raw json.RawMessage) json.RawMessage {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || string(trimmed) == "null" {
		return nil
	}
	switch trimmed[0] {
	case '[', '{':
		// Already a valid JSON collection — pass through.
		return trimmed
	case '"':
		// JSON-encoded string: decode, split on comma, re-encode as array.
		var s string
		if err := json.Unmarshal(trimmed, &s); err != nil {
			return nil
		}
		parts := strings.Split(s, ",")
		cleaned := make([]string, 0, len(parts))
		for _, p := range parts {
			if v := strings.TrimSpace(p); v != "" {
				cleaned = append(cleaned, v)
			}
		}
		if len(cleaned) == 0 {
			return nil
		}
		out, err := json.Marshal(cleaned)
		if err != nil {
			return nil
		}
		return out
	default:
		return nil
	}
}

// stringifyRequestAttributes converts a map[string]json.RawMessage to
// map[string]string by un-quoting JSON strings and converting numbers/booleans
// to their string representations. This is necessary because the v3 PIP export
// allows non-string requestAttributes values (e.g. numeric constants), while
// pips.SimplifiedPIP.RequestAttributes is map[string]string.
func stringifyRequestAttributes(raw map[string]json.RawMessage) map[string]string {
	if len(raw) == 0 {
		return nil
	}
	out := make(map[string]string, len(raw))
	for k, v := range raw {
		trimmed := bytes.TrimSpace(v)
		if len(trimmed) == 0 {
			continue
		}
		switch trimmed[0] {
		case '"':
			var s string
			if err := json.Unmarshal(trimmed, &s); err == nil {
				out[k] = s
				continue
			}
		}
		// For numbers, booleans, and other literals: use the raw JSON token
		// stripped of surrounding quotes, converted to string.
		out[k] = rawJSONToString(trimmed)
	}
	return out
}

// rawJSONToString converts a non-string JSON value to its string representation.
// Numbers and booleans are stripped of precision loss by using strconv.
func rawJSONToString(raw json.RawMessage) string {
	s := string(raw)
	// Try integer first.
	if i, err := strconv.ParseInt(s, 10, 64); err == nil {
		return strconv.FormatInt(i, 10)
	}
	// Try float.
	if f, err := strconv.ParseFloat(s, 64); err == nil {
		return strconv.FormatFloat(f, 'f', -1, 64)
	}
	// Boolean or null.
	return s
}

func coalesce(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
