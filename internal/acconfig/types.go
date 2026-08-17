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

// Package acconfig converts access-control v3 config API responses into the
// simplified-policy and PIP formats consumed by OPA. It depends only on the Go
// standard library and on the authz-agent internal packages.
//
// The source API is documented in authz-agent-ADR-0071 (pull loop).
package acconfig

import "encoding/json"

// V3PolicySetsResponse is the envelope returned by
// GET /access/v3/config/policySets.
type V3PolicySetsResponse struct {
	Hash                      string        `json:"hash"`
	LastModificationTimestamp string        `json:"lastModificationTimestamp"`
	PolicySets                []PolicySetV3 `json:"policySets"`
}

// PolicySetV3 is one element of the policySets array. It is byte-identical to
// the v1 export element (both paths call the same Java converter). The subset
// of fields read by this package is listed below; unknown fields are ignored.
//
// Absent "type" means DEFAULT (not SIMPLIFIED): the policy set is silently
// skipped because the agent evaluates the simplified model only.
type PolicySetV3 struct {
	PolicySetID        string     `json:"policySetId"`
	Name               string     `json:"name"`
	Type               string     `json:"type"`   // "DEFAULT" | "SIMPLIFIED"; absent = DEFAULT
	Domain             string     `json:"domain"` // component name; may be absent on DEFAULT sets
	Status             string     `json:"status"`
	Target             string     `json:"target"`
	CombiningAlgorithm string     `json:"combiningAlgorithm"`
	TenantID           string     `json:"tenantId"`
	Policies           []PolicyV3 `json:"policies"`
}

// PolicyV3 is one policy element inside a policy set.
type PolicyV3 struct {
	PolicyID           string   `json:"policyId"`
	Target             string   `json:"target"`
	CombiningAlgorithm string   `json:"combiningAlgorithm"`
	Rules              []RuleV3 `json:"rules"`
}

// RuleV3 is one rule element inside a policy.
type RuleV3 struct {
	RuleID            string  `json:"ruleId"`
	Name              string  `json:"name"`
	Target            string  `json:"target"`
	Condition         *string `json:"condition"` // null ⇒ absent ⇒ no condition
	Effect            string  `json:"effect"`
	RSQLPredicate     string  `json:"rsqlPredicate"`     // optional
	SQLPredicate      string  `json:"sqlPredicate"`      // optional
	MongoDBPredicate  string  `json:"mongodbPredicate"`  // optional
	QueryDSLPredicate string  `json:"querydslPredicate"` // optional
	Predicate         string  `json:"predicate"`         // legacy CLANG/querydsl; kept for completeness, not mapped
	// ProductMapping and other non-SIMPLIFIED fields are ignored.
	ProductMapping json.RawMessage `json:"productMapping,omitempty"`
}

// V3PIPsResponse is the envelope returned by GET /access/v3/config/pips.
type V3PIPsResponse struct {
	Hash                      string  `json:"hash"`
	LastModificationTimestamp string  `json:"lastModificationTimestamp"`
	PIPs                      []PIPV3 `json:"pips"`
}

// PIPV3 is one element of the pips array. It maps closely to pips.SimplifiedPIP
// but the v3 wire format adds fields that the agent does not handle (cacheable,
// cachePeriod, tenantId, productMapping) and may represent headers as a
// comma-separated string rather than a JSON array.
type PIPV3 struct {
	Name         string          `json:"name"`
	PipType      string          `json:"pipType"`
	URL          string          `json:"url"`
	HTTPMethod   string          `json:"httpMethod"`
	Header       string          `json:"header"`
	Claim        string          `json:"claim"`
	BeanName     string          `json:"beanName"`
	DefaultValue json.RawMessage `json:"defaultValue,omitempty"`
	Domain       string          `json:"domain"`
	TenantID     string          `json:"tenantId"` // ignored; all tenants are merged
	Type         string          `json:"type"`
	JsonPath     string          `json:"jsonPath"`
	// RequestAttributes in the v3 export may contain non-string values (e.g. a
	// JSON number). The converter stringifies each value before writing into
	// pips.SimplifiedPIP.RequestAttributes which is map[string]string.
	RequestAttributes map[string]json.RawMessage `json:"requestAttributes,omitempty"`
	// Headers in the v3 export may be a comma-separated string ("A,B,C") or a
	// JSON array/object. The converter normalises it to a JSON array.
	Headers json.RawMessage `json:"headers,omitempty"`
	// ── PDP contract extension (authz-agent-ADR-0066..0069) ──────────────
	// Not part of access-control's contract: its authoritative
	// PolicyInformationPointJson declares no query/body/timeoutSeconds/response,
	// so a real access-control never sends these and they stay zero here.
	//
	// They are parsed because the authz-policy-admin does serve them
	// (authz-agent-ADR-0073), which is what gives the extension a delivery path
	// a test can drive. Parsing a field the production source never emits costs
	// nothing and keeps one shape for both sources; the alternative — a second
	// PIP type for the stub — would let the two drift apart silently.
	Query          map[string]string `json:"query,omitempty"`
	Body           json.RawMessage   `json:"body,omitempty"`
	TimeoutSeconds *int              `json:"timeoutSeconds,omitempty"`
	Response       json.RawMessage   `json:"response,omitempty"`

	// Cache-related fields: present in the export, ignored by the agent
	// (ADR-0052 / D-AF-Y).
	Cacheable   bool `json:"cacheable"`
	CachePeriod int  `json:"cachePeriod"`
	// MAPPING PIP field: present in the export but not supported.
	ProductMapping json.RawMessage `json:"productMapping,omitempty"`
}
