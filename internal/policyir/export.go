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

package policyir

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
)

// Export is the configuration of every tenant that a v3 configuration export
// carries.
type Export struct {
	// Trees maps a tenant ID, exactly as the export writes it, to the tree of
	// that tenant.
	Trees map[string]*Tree
	// Failed maps a tenant ID to the reason no tree of that tenant could be
	// built. Such a tenant has no entry in Trees.
	Failed map[string]error
	// Orphans lists the elements that name no tenant, which belong to no
	// tree.
	Orphans []error
}

// FromRegular reads the documents of GET /access/v3/config/policySets and GET
// /access/v3/config/pips into one tree per tenant. It returns an error only
// when a document is not a JSON object with the array policySets or pips; an
// element that cannot be read fails its own tenant and no other.
//
// Every top-level set applies except one whose status is INACTIVE, DRAFT, or
// ARCHIVED, whatever its type; a nested set applies in any status. A set of
// type SIMPLIFIED in the shape the PAP writes for simplified policies becomes
// a [SimplifiedGroup] again. That shape is a set with the target
// resourceType == 'T', the algorithm DENY_UNLESS_PERMIT, and neither iterate
// nor nested sets; a policy per operation with the same algorithm and the
// target operation == 'O', or true for ALL; and, for each simplified policy of
// that operation, an ALLOW rule with the target
// subject.roles CONTAINS ANY 'r1','r2', its condition, and its predicates,
// with no status, no customPredicate, and no predicate field. Each target is
// the exact text the PAP writes, so a policy target operation == 'ALL' or
// operation EQUALS 'O' is another shape. A SIMPLIFIED set of any other shape is
// read as a regular set. A
// PIP without a pipType is GENERAL, and when a tenant declares one name twice
// the first declaration counts.
func FromRegular(policySets, pips []byte) (*Export, error) {
	var setsDoc struct {
		PolicySets *[]json.RawMessage `json:"policySets"`
	}
	if err := json.Unmarshal(policySets, &setsDoc); err != nil || setsDoc.PolicySets == nil {
		return nil, fmt.Errorf("policy sets export: not an object with a policySets array: %v", err)
	}
	var pipsDoc struct {
		PIPs *[]json.RawMessage `json:"pips"`
	}
	if err := json.Unmarshal(pips, &pipsDoc); err != nil || pipsDoc.PIPs == nil {
		return nil, fmt.Errorf("PIP export: not an object with a pips array: %v", err)
	}

	type tenant struct {
		simplified []*SimplifiedGroup
		sets       []*PolicySet
		pips       []*PIP
		vars       int
		err        error
	}
	tenants := map[string]*tenant{}
	var order []string
	out := &Export{Trees: map[string]*Tree{}, Failed: map[string]error{}}
	get := func(kind string, i int, raw json.RawMessage) *tenant {
		var head struct {
			TenantID *string `json:"tenantId"`
		}
		if err := json.Unmarshal(raw, &head); err != nil || head.TenantID == nil {
			out.Orphans = append(out.Orphans, fmt.Errorf("%s %d: no tenantId string", kind, i))
			return nil
		}
		t, ok := tenants[*head.TenantID]
		if !ok {
			t = &tenant{}
			tenants[*head.TenantID] = t
			order = append(order, *head.TenantID)
		}
		return t
	}

	for i, raw := range *setsDoc.PolicySets {
		t := get("policy set", i, raw)
		if t == nil || t.err != nil {
			continue
		}
		var s exportSet
		if err := json.Unmarshal(raw, &s); err != nil {
			t.err = fmt.Errorf("policy set %d: %w", i, err)
			continue
		}
		if !topLevelApplies(s.Status) {
			continue
		}
		if g, ok := simplifiedGroup(&s); ok {
			t.simplified = append(t.simplified, g)
			continue
		}
		b := setBuilder{vars: &t.vars}
		ps, err := b.set(&s, "")
		if err != nil {
			t.err = fmt.Errorf("policy set %q: %w", s.PolicySetID, err)
			continue
		}
		t.sets = append(t.sets, ps)
	}
	for i, raw := range *pipsDoc.PIPs {
		t := get("pip", i, raw)
		if t == nil || t.err != nil {
			continue
		}
		p, err := readPIP(raw)
		if err != nil {
			t.err = fmt.Errorf("pip %d: %w", i, err)
			continue
		}
		if !slices.ContainsFunc(t.pips, func(q *PIP) bool { return q.Name == p.Name }) {
			t.pips = append(t.pips, p)
		}
	}
	for _, id := range order {
		t := tenants[id]
		if t.err != nil {
			out.Failed[id] = t.err
			continue
		}
		tree, err := NewTree(t.simplified, t.sets, t.pips)
		if err != nil {
			out.Failed[id] = err
			continue
		}
		out.Trees[id] = tree
	}
	return out, nil
}

// topLevelApplies reports whether a top-level set of status applies: every
// status except INACTIVE, DRAFT, and ARCHIVED, including an absent one.
func topLevelApplies(status string) bool {
	switch status {
	case "INACTIVE", "DRAFT", "ARCHIVED":
		return false
	default:
		return true
	}
}

type exportSet struct {
	PolicySetID        string         `json:"policySetId"`
	Name               string         `json:"name"`
	Type               string         `json:"type"`
	Domain             string         `json:"domain"`
	Component          *string        `json:"component"`
	Status             string         `json:"status"`
	Target             *string        `json:"target"`
	CombiningAlgorithm string         `json:"combiningAlgorithm"`
	Iterate            *exportIterate `json:"iterate"`
	Policies           []exportPolicy `json:"policies"`
	PolicySets         []exportSet    `json:"policySets"`
}

type exportIterate struct {
	Foreach            string `json:"foreach"`
	CombiningAlgorithm string `json:"combiningAlgorithm"`
}

type exportPolicy struct {
	PolicyID           string       `json:"policyId"`
	Name               string       `json:"name"`
	Status             string       `json:"status"`
	Target             *string      `json:"target"`
	CombiningAlgorithm string       `json:"combiningAlgorithm"`
	Rules              []exportRule `json:"rules"`
}

type exportRule struct {
	RuleID            string           `json:"ruleId"`
	Name              string           `json:"name"`
	Status            string           `json:"status"`
	RuleType          string           `json:"ruleType"`
	Target            *string          `json:"target"`
	Condition         *string          `json:"condition"`
	Effect            string           `json:"effect"`
	RSQLPredicate     string           `json:"rsqlPredicate"`
	SQLPredicate      string           `json:"sqlPredicate"`
	MongoDBPredicate  string           `json:"mongodbPredicate"`
	Predicate         string           `json:"predicate"`
	QueryDSLPredicate string           `json:"querydslPredicate"`
	CustomPredicate   *json.RawMessage `json:"customPredicate"`
}

const ruleTypeFrontend = "APPLICABLE_FOR_FRONTEND"

// condition parses text at place, and turns text the parser refuses into a
// condition of one [Unsupported] atom of [FormSyntax].
func condition(text *string, place Place, iterVar string) *Condition {
	if text == nil {
		return nil
	}
	c, err := ParseCondition(*text, place, iterVar)
	if err != nil {
		return &Condition{Place: place, Disjuncts: [][]Atom{{Unsupported{Form: FormSyntax, Text: *text}}}}
	}
	return c
}

func algorithmOf(a string) (Algorithm, error) {
	if !slices.Contains(algorithms, Algorithm(a)) {
		return "", fmt.Errorf("combiningAlgorithm %q unknown", a)
	}
	return Algorithm(a), nil
}

type setBuilder struct {
	vars *int
}

// set builds s. iterVar is the var of the innermost iterate around s, which
// its own target reads; its children read the var of its own iterate.
func (b setBuilder) set(s *exportSet, iterVar string) (*PolicySet, error) {
	alg, err := algorithmOf(s.CombiningAlgorithm)
	if err != nil {
		return nil, err
	}
	ps := &PolicySet{
		ID: s.PolicySetID, Name: s.Name, Domain: s.Domain, Algorithm: alg,
		Target: condition(s.Target, PlaceSetTarget, iterVar),
	}
	inner := iterVar
	if it := s.Iterate; it != nil {
		ia, err := algorithmOf(it.CombiningAlgorithm)
		switch {
		case it.Foreach != "subject.permissionScope":
			ps.AlwaysFails = fmt.Sprintf("iterate foreach %q", it.Foreach)
		case it.CombiningAlgorithm == "":
			ps.AlwaysFails = "iterate without a combiningAlgorithm"
		case err != nil:
			ps.AlwaysFails = "iterate " + err.Error()
		default:
			*b.vars++
			inner = fmt.Sprintf("iterate%d", *b.vars)
			ps.Iterate = &Iterate{Var: inner, Algorithm: ia}
		}
		if ps.AlwaysFails != "" {
			return ps, nil
		}
	}
	for i := range s.Policies {
		p, err := b.policy(&s.Policies[i], inner)
		if err != nil {
			return nil, fmt.Errorf("policy %q: %w", s.Policies[i].PolicyID, err)
		}
		ps.Policies = append(ps.Policies, p)
	}
	for i := range s.PolicySets {
		k, err := b.set(&s.PolicySets[i], inner)
		if err != nil {
			return nil, fmt.Errorf("policy set %q: %w", s.PolicySets[i].PolicySetID, err)
		}
		ps.Sets = append(ps.Sets, k)
	}
	return ps, nil
}

func (b setBuilder) policy(p *exportPolicy, iterVar string) (*Policy, error) {
	alg, err := algorithmOf(p.CombiningAlgorithm)
	if err != nil {
		return nil, err
	}
	out := &Policy{
		ID: p.PolicyID, Name: p.Name, Algorithm: alg, Status: p.Status,
		Target: condition(p.Target, PlacePolicyTarget, iterVar),
	}
	for i := range p.Rules {
		r := &p.Rules[i]
		if !slices.Contains(effects, Effect(r.Effect)) {
			return nil, fmt.Errorf("rule %q: effect %q unknown", r.RuleID, r.Effect)
		}
		preds, err := predicates(r, r.Predicate)
		if err != nil {
			return nil, fmt.Errorf("rule %q: %w", r.RuleID, err)
		}
		out.Rules = append(out.Rules, &Rule{
			ID: r.RuleID, Name: r.Name, Effect: Effect(r.Effect), Status: r.Status,
			Frontend:   r.RuleType == ruleTypeFrontend,
			Target:     condition(r.Target, PlaceRuleTarget, iterVar),
			Condition:  condition(r.Condition, PlaceRuleCondition, iterVar),
			Predicates: preds,
		})
	}
	return out, nil
}

// predicates reads the predicates of r, with querydsl as the template of the
// querydsl dialect: the predicate field of a regular rule, the
// querydslPredicate field of a simplified policy. An empty template is no
// template.
func predicates(r *exportRule, querydsl string) (Predicates, error) {
	var p Predicates
	for d, text := range map[Dialect]string{
		DialectRSQL: r.RSQLPredicate, DialectSQL: r.SQLPredicate, DialectMongoDB: r.MongoDBPredicate,
		DialectQueryDSL: querydsl,
	} {
		if text != "" {
			if p.Text == nil {
				p.Text = map[Dialect]string{}
			}
			p.Text[d] = text
		}
	}
	if r.CustomPredicate != nil && !isNull(*r.CustomPredicate) {
		var c struct {
			Predicate string                     `json:"predicate"`
			Params    map[string]json.RawMessage `json:"params"`
		}
		if err := json.Unmarshal(*r.CustomPredicate, &c); err != nil {
			return Predicates{}, fmt.Errorf("customPredicate: %w", err)
		}
		cp := &CustomPredicate{Predicate: c.Predicate}
		for k, v := range c.Params {
			if cp.Params == nil {
				cp.Params = map[string]string{}
			}
			cp.Params[k] = compact(v)
		}
		p.Custom = cp
	}
	return p, nil
}

func isNull(raw json.RawMessage) bool {
	return bytes.Equal(bytes.TrimSpace(raw), []byte("null"))
}

func compact(raw json.RawMessage) string {
	var b bytes.Buffer
	if err := json.Compact(&b, raw); err != nil {
		return string(raw)
	}
	return b.String()
}

// simplifiedGroup returns the simplified policies s holds, and false when s is
// not a set of type SIMPLIFIED in the shape the PAP writes for them.
func simplifiedGroup(s *exportSet) (*SimplifiedGroup, bool) {
	if s.Type != "SIMPLIFIED" || s.Iterate != nil || len(s.PolicySets) > 0 || s.Target == nil ||
		s.CombiningAlgorithm != string(AlgorithmDenyUnlessPermit) {
		return nil, false
	}
	rt, ok := onlyEquality(*s.Target, ResourceType{})
	if !ok || *s.Target != resourceTypeTarget(rt) {
		return nil, false
	}
	g := &SimplifiedGroup{Domain: s.Domain, ResourceType: rt}
	if s.Component != nil {
		g.Component = *s.Component
	}
	for _, p := range s.Policies {
		if p.Target == nil || p.Status != "" || p.CombiningAlgorithm != string(AlgorithmDenyUnlessPermit) {
			return nil, false
		}
		op := "ALL"
		if *p.Target != "true" {
			if op, ok = onlyEquality(*p.Target, Operation{}); !ok || *p.Target != operationTarget(op) {
				return nil, false
			}
		}
		for i := range p.Rules {
			r := &p.Rules[i]
			if r.Effect != string(EffectAllow) || r.Status != "" || r.Predicate != "" || r.CustomPredicate != nil ||
				r.Target == nil {
				return nil, false
			}
			roles, ok := rolesOf(*r.Target)
			if !ok || *r.Target != rolesTarget(roles) {
				return nil, false
			}
			preds, _ := predicates(r, r.QueryDSLPredicate)
			g.Policies = append(g.Policies, &SimplifiedPolicy{
				ID: r.RuleID, Frontend: r.RuleType == ruleTypeFrontend, Operation: op, Roles: roles,
				Condition: condition(r.Condition, PlaceSimplified, ""), Predicates: preds,
			})
		}
	}
	return g, true
}

// resourceTypeTarget is the set target the PAP writes for the simplified
// policies of resource type rt, "ALL" included.
func resourceTypeTarget(rt string) string {
	return "resourceType == '" + rt + "'"
}

// operationTarget is the policy target the PAP writes for the simplified
// policies of operation op. For ALL it is true, never operation == 'ALL'.
func operationTarget(op string) string {
	if op == "ALL" {
		return "true"
	}
	return "operation == '" + op + "'"
}

// rolesTarget is the rule target the PAP writes for a simplified policy of
// roles.
func rolesTarget(roles []string) string {
	return "subject.roles CONTAINS ANY '" + strings.Join(roles, "','") + "'"
}

// onlyEquality returns the string s in text when text is exactly left == 's'.
func onlyEquality(text string, left Operand) (string, bool) {
	c, err := ParseCondition(text, PlaceSetTarget, "")
	if err != nil || len(c.Disjuncts) != 1 || len(c.Disjuncts[0]) != 1 {
		return "", false
	}
	cmp, ok := c.Disjuncts[0][0].(Compare)
	if !ok || cmp.Op != OpEQ || cmp.Left != left {
		return "", false
	}
	s, ok := cmp.Right.(String)
	return s.Value, ok
}

// rolesOf returns the roles of text when text is exactly
// subject.roles CONTAINS ANY 'r1','r2'.
func rolesOf(text string) ([]string, bool) {
	c, err := ParseCondition(text, PlaceRuleTarget, "")
	if err != nil || len(c.Disjuncts) != 1 || len(c.Disjuncts[0]) != 1 {
		return nil, false
	}
	cmp, ok := c.Disjuncts[0][0].(Compare)
	if !ok || cmp.Op != OpContainsAny || cmp.Left != (Subject{Attr: SubjectRoles}) {
		return nil, false
	}
	list, ok := cmp.Right.(List)
	if !ok {
		return nil, false
	}
	roles := make([]string, 0, len(list.Items))
	for _, it := range list.Items {
		s, ok := it.(String)
		if !ok {
			return nil, false
		}
		roles = append(roles, s.Value)
	}
	return roles, true
}

type exportPIP struct {
	Name              *string                    `json:"name"`
	PipType           string                     `json:"pipType"`
	Type              string                     `json:"type"`
	Domain            string                     `json:"domain"`
	URL               string                     `json:"url"`
	HTTPMethod        string                     `json:"httpMethod"`
	Header            string                     `json:"header"`
	Claim             string                     `json:"claim"`
	BeanName          string                     `json:"beanName"`
	JSONPath          string                     `json:"jsonPath"`
	ResourceType      string                     `json:"resourceType"`
	DefaultValue      json.RawMessage            `json:"defaultValue"`
	Headers           json.RawMessage            `json:"headers"`
	RequestAttributes map[string]json.RawMessage `json:"requestAttributes"`
	ProductMapping    json.RawMessage            `json:"productMapping"`
	CustomMapping     json.RawMessage            `json:"customMapping"`

	// The fields of the agent's own PIP extension, which the legacy service
	// does not have.
	Query          json.RawMessage `json:"query"`
	Body           json.RawMessage `json:"body"`
	TimeoutSeconds json.RawMessage `json:"timeoutSeconds"`
	Response       json.RawMessage `json:"response"`
}

// readPIP reads one PIP declaration of the export.
func readPIP(raw json.RawMessage) (*PIP, error) {
	var e exportPIP
	if err := json.Unmarshal(raw, &e); err != nil {
		return nil, err
	}
	if e.Name == nil {
		return nil, errors.New("no name")
	}
	p := &PIP{
		Name: *e.Name, Type: PIPType(e.PipType), ReturnType: e.Type, Domain: e.Domain, URL: e.URL,
		HTTPMethod: e.HTTPMethod, Header: e.Header, Claim: e.Claim, BeanName: e.BeanName, JSONPath: e.JSONPath,
		ResourceType: e.ResourceType, DefaultValue: present(e.DefaultValue),
		ProductMapping: present(e.ProductMapping), CustomMapping: present(e.CustomMapping),
	}
	if p.Type == "" {
		p.Type = PIPGeneral
	}
	if !slices.Contains(pipTypes, p.Type) {
		return nil, fmt.Errorf("%q: pipType %q unknown", p.Name, p.Type)
	}
	var unsupported []string
	switch h := present(e.Headers); {
	case h == "":
	case strings.HasPrefix(h, `"`):
		if err := json.Unmarshal(e.Headers, &p.Headers); err != nil {
			return nil, fmt.Errorf("%q: headers: %w", p.Name, err)
		}
	case strings.HasPrefix(h, "["):
		var names []string
		if err := json.Unmarshal(e.Headers, &names); err != nil {
			return nil, fmt.Errorf("%q: headers: %w", p.Name, err)
		}
		p.Headers = strings.Join(names, ",")
	case strings.HasPrefix(h, "{"):
		unsupported = append(unsupported, "headers object")
	default:
		return nil, fmt.Errorf("%q: headers %s is neither a string, a list, nor an object", p.Name, h)
	}
	for k, v := range e.RequestAttributes {
		if p.RequestAttributes == nil {
			p.RequestAttributes = map[string]string{}
		}
		p.RequestAttributes[k] = compact(v)
	}
	for _, f := range []struct {
		name string
		raw  json.RawMessage
	}{{"query", e.Query}, {"body", e.Body}, {"timeoutSeconds", e.TimeoutSeconds}, {"response", e.Response}} {
		if present(f.raw) != "" {
			unsupported = append(unsupported, f.name)
		}
	}
	p.Unsupported = strings.Join(unsupported, ", ")
	return p, nil
}

// present returns raw as compact JSON, or empty when raw is absent or null:
// the export writes an absent field as null.
func present(raw json.RawMessage) string {
	if len(raw) == 0 || isNull(raw) {
		return ""
	}
	return compact(raw)
}
