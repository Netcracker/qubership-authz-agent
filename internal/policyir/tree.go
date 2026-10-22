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
	"fmt"
	"slices"
	"strings"
)

// Algorithm is a combining algorithm.
type Algorithm string

// The combining algorithms. AlgorithmAbsent is a node that names none; the
// specification's profile decides how such a node combines its children.
const (
	AlgorithmAbsent           Algorithm = ""
	AlgorithmDenyOverrides    Algorithm = "DENY_OVERRIDES"
	AlgorithmPermitOverrides  Algorithm = "PERMIT_OVERRIDES"
	AlgorithmDenyUnlessPermit Algorithm = "DENY_UNLESS_PERMIT"
	AlgorithmPermitUnlessDeny Algorithm = "PERMIT_UNLESS_DENY"
)

var algorithms = []Algorithm{
	AlgorithmAbsent, AlgorithmDenyOverrides, AlgorithmPermitOverrides, AlgorithmDenyUnlessPermit,
	AlgorithmPermitUnlessDeny,
}

// Effect is the effect of a rule as written. Only ALLOW and DENY name an
// outcome; the specification's profile decides what the others and an absent
// effect do.
type Effect string

// The effects the PAP accepts, and EffectAbsent for a rule that names none.
const (
	EffectAbsent             Effect = ""
	EffectAllow              Effect = "ALLOW"
	EffectDeny               Effect = "DENY"
	EffectNotApplicable      Effect = "NOT_APPLICABLE"
	EffectUseFilterCondition Effect = "USE_FILTER_CONDITION"
)

var effects = []Effect{EffectAbsent, EffectAllow, EffectDeny, EffectNotApplicable, EffectUseFilterCondition}

// Dialect is a dialect of filter predicates.
type Dialect string

// The dialects, each read from its own field of a rule: rsqlPredicate,
// sqlPredicate, mongodbPredicate, and predicate for querydsl.
const (
	DialectRSQL     Dialect = "rsql"
	DialectSQL      Dialect = "sql"
	DialectMongoDB  Dialect = "mongodb"
	DialectQueryDSL Dialect = "querydsl"
)

// Dialects lists every dialect, in the order a dump prints them.
var Dialects = []Dialect{DialectRSQL, DialectSQL, DialectMongoDB, DialectQueryDSL}

// Predicates are the filter predicates of a rule or a simplified policy.
type Predicates struct {
	// Text maps a dialect to its template as written, placeholders unexpanded.
	// A dialect without a template is not a key.
	Text map[Dialect]string
	// Custom is the customPredicate, or nil.
	Custom *CustomPredicate
}

// CustomPredicate is a customPredicate: the predicate name and its parameters.
// Each parameter value is the JSON value as written, which the PAP accepts as
// any JSON type.
type CustomPredicate struct {
	Predicate string
	Params    map[string]string
}

// Tree is the effective policy configuration of one tenant. [NewTree] builds
// it.
type Tree struct {
	Simplified []*SimplifiedGroup
	Sets       []*PolicySet
	PIPs       []*PIP
}

// SimplifiedGroup is the simplified policies of one component that share a
// resource type, as one top-level node. ResourceType may be "ALL".
type SimplifiedGroup struct {
	Domain       string
	Component    string
	ResourceType string
	Policies     []*SimplifiedPolicy
}

// SimplifiedPolicy is one simplified policy. Its effect is ALLOW.
type SimplifiedPolicy struct {
	ID string
	// Operation is the operation as written, possibly "ALL", or empty when the
	// policy names none.
	Operation string
	Roles     []string
	// Condition is at [PlaceSimplified], or nil.
	Condition  *Condition
	Predicates Predicates
}

// PolicySet is a policy set: top-level, or nested in another one.
type PolicySet struct {
	ID        string
	Name      string
	Domain    string
	Algorithm Algorithm
	// Target is at [PlaceSetTarget], or nil when the set applies to any request.
	Target *Condition
	// Iterate is the set's iterate, or nil.
	Iterate *Iterate
	// AlwaysFails is the reason the legacy service never evaluates this set,
	// whatever the request; empty for a set it evaluates. Such a set is a
	// permanent source failure under its target and holds no policies, no sets,
	// and no iterate.
	AlwaysFails string
	Policies    []*Policy
	Sets        []*PolicySet
}

// Iterate is the iterate of a set: the set is evaluated once per assignment of
// subject.permissionScope, and Algorithm combines the passes. Var names the
// pass for [PassValue] and is unique in the tree.
//
// The legacy service evaluates only iterate over subject.permissionScope with
// an algorithm, so a frontend turns any other iterate into
// [PolicySet.AlwaysFails].
type Iterate struct {
	Var       string
	Algorithm Algorithm
}

// Policy is a policy of a policy set.
type Policy struct {
	ID        string
	Name      string
	Algorithm Algorithm
	// Target is at [PlacePolicyTarget], or nil.
	Target *Condition
	Rules  []*Rule
}

// Rule is a rule of a policy.
type Rule struct {
	ID     string
	Name   string
	Effect Effect
	// Target is at [PlaceRuleTarget], or nil.
	Target *Condition
	// Condition is at [PlaceRuleCondition], or nil.
	Condition  *Condition
	Predicates Predicates
}

// PIPType is the pipType of a PIP declaration.
type PIPType string

// The PIP types the PAP accepts. A frontend reads an absent pipType as
// GENERAL.
const (
	PIPGeneral         PIPType = "GENERAL"
	PIPFiltered        PIPType = "FILTERED"
	PIPHeader          PIPType = "HEADER"
	PIPToken           PIPType = "TOKEN"
	PIPMapping         PIPType = "MAPPING"
	PIPPermissionScope PIPType = "PERMISSION_SCOPE"
)

var pipTypes = []PIPType{PIPGeneral, PIPFiltered, PIPHeader, PIPToken, PIPMapping, PIPPermissionScope}

// PIP is a PIP declaration of the tenant. Each field holds the value as
// written, empty when absent; which fields a type reads is the specification's.
type PIP struct {
	// Name is the declared name, starting with "subject.".
	Name string
	Type PIPType

	// Claim is the token claim of a TOKEN PIP.
	Claim string
	// Header is the request header of a HEADER PIP.
	Header string
	// DefaultValue is the default of a TOKEN or HEADER PIP, or nil.
	DefaultValue *string

	URL        string
	HTTPMethod string
	BeanName   string
	JSONPath   string
	// ReturnType is the type field: UUID, REGULAR, JSON, or empty.
	ReturnType string
	// ForwardHeaders are the names of the request headers the call forwards,
	// which the export writes as one comma-separated string.
	ForwardHeaders []string
	// RequestAttributes maps an attribute name to its JSON value as written.
	RequestAttributes map[string]string

	// ProductMapping and CustomMapping are the JSON objects of a MAPPING PIP as
	// written, or empty.
	ProductMapping string
	CustomMapping  string
}

// PIP returns the declaration named name, and false when the tree declares
// none.
func (t *Tree) PIP(name string) (*PIP, bool) {
	for _, p := range t.PIPs {
		if p.Name == name {
			return p, true
		}
	}
	return nil, false
}

// NewTree returns the tree of simplified groups, sets, and PIP declarations,
// which it shares rather than copies. It returns an error that names the
// offending node when any of these is violated:
//
//   - every node is non-nil, and every algorithm, effect, dialect, and PIP type
//     is one this package declares;
//   - every condition is valid as [NewCondition] checks it, and stands at the
//     place of its position: a set target at [PlaceSetTarget], and so on;
//   - every [Iterate.Var] is non-empty and unique in the tree, the algorithm of
//     an iterate is not absent, and every [PassValue] names the var of an
//     enclosing set;
//   - a set with [PolicySet.AlwaysFails] has no policies, sets, or iterate;
//   - PIP names start with "subject." and are unique.
func NewTree(simplified []*SimplifiedGroup, sets []*PolicySet, pips []*PIP) (*Tree, error) {
	t := &Tree{Simplified: simplified, Sets: sets, PIPs: pips}
	if err := t.validate(); err != nil {
		return nil, err
	}
	return t, nil
}

type checker struct {
	vars map[string]bool
}

func (t *Tree) validate() error {
	names := map[string]bool{}
	for i, p := range t.PIPs {
		if p == nil {
			return fmt.Errorf("pip %d: nil", i)
		}
		if !strings.HasPrefix(p.Name, "subject.") {
			return fmt.Errorf("pip %q: name lacks the subject. prefix", p.Name)
		}
		if names[p.Name] {
			return fmt.Errorf("pip %q: declared twice", p.Name)
		}
		names[p.Name] = true
		if !slices.Contains(pipTypes, p.Type) {
			return fmt.Errorf("pip %q: pipType %q unknown", p.Name, p.Type)
		}
	}
	c := checker{vars: map[string]bool{}}
	for i, g := range t.Simplified {
		if g == nil {
			return fmt.Errorf("simplified group %d: nil", i)
		}
		for j, p := range g.Policies {
			if p == nil {
				return fmt.Errorf("simplified %q/%q/%q: policy %d: nil", g.Domain, g.Component, g.ResourceType, j)
			}
			where := simplifiedPath(g, p)
			if err := c.condition(where+" > condition", p.Condition, PlaceSimplified, nil); err != nil {
				return err
			}
			if err := checkPredicates(where, p.Predicates); err != nil {
				return err
			}
		}
	}
	for i, s := range t.Sets {
		if s == nil {
			return fmt.Errorf("set %d: nil", i)
		}
		if err := c.set("", s, nil); err != nil {
			return err
		}
	}
	return nil
}

func (c *checker) set(parent string, s *PolicySet, bound []string) error {
	here := join(parent, fmt.Sprintf("set %q", s.ID))
	if !slices.Contains(algorithms, s.Algorithm) {
		return fmt.Errorf("%s: algorithm %q unknown", here, s.Algorithm)
	}
	if s.AlwaysFails != "" && (s.Iterate != nil || len(s.Policies) > 0 || len(s.Sets) > 0) {
		return fmt.Errorf("%s: a set that always fails has children or an iterate", here)
	}
	if err := c.condition(here+" > target", s.Target, PlaceSetTarget, bound); err != nil {
		return err
	}
	if it := s.Iterate; it != nil {
		switch {
		case it.Var == "":
			return fmt.Errorf("%s: iterate: no var", here)
		case c.vars[it.Var]:
			return fmt.Errorf("%s: iterate: var %q bound twice in the tree", here, it.Var)
		case it.Algorithm == AlgorithmAbsent || !slices.Contains(algorithms, it.Algorithm):
			return fmt.Errorf("%s: iterate: algorithm %q is not one of the four", here, it.Algorithm)
		}
		c.vars[it.Var] = true
		bound = append(slices.Clip(bound), it.Var)
	}
	for i, p := range s.Policies {
		if p == nil {
			return fmt.Errorf("%s: policy %d: nil", here, i)
		}
		if err := c.policy(here, p, bound); err != nil {
			return err
		}
	}
	for i, k := range s.Sets {
		if k == nil {
			return fmt.Errorf("%s: set %d: nil", here, i)
		}
		if err := c.set(here, k, bound); err != nil {
			return err
		}
	}
	return nil
}

func (c *checker) policy(parent string, p *Policy, bound []string) error {
	here := join(parent, fmt.Sprintf("policy %q", p.ID))
	if !slices.Contains(algorithms, p.Algorithm) {
		return fmt.Errorf("%s: algorithm %q unknown", here, p.Algorithm)
	}
	if err := c.condition(here+" > target", p.Target, PlacePolicyTarget, bound); err != nil {
		return err
	}
	for i, r := range p.Rules {
		if r == nil {
			return fmt.Errorf("%s: rule %d: nil", here, i)
		}
		rp := join(here, fmt.Sprintf("rule %q", r.ID))
		if !slices.Contains(effects, r.Effect) {
			return fmt.Errorf("%s: effect %q unknown", rp, r.Effect)
		}
		if err := c.condition(rp+" > target", r.Target, PlaceRuleTarget, bound); err != nil {
			return err
		}
		if err := c.condition(rp+" > condition", r.Condition, PlaceRuleCondition, bound); err != nil {
			return err
		}
		if err := checkPredicates(rp, r.Predicates); err != nil {
			return err
		}
	}
	return nil
}

func (c *checker) condition(where string, cond *Condition, place Place, bound []string) error {
	if cond == nil {
		return nil
	}
	if err := validateCondition(cond); err != nil {
		return fmt.Errorf("%s: %w", where, err)
	}
	if cond.Place != place {
		return fmt.Errorf("%s: place %q, want %q", where, cond.Place, place)
	}
	for _, d := range cond.Disjuncts {
		for _, a := range d {
			cmp, ok := a.(Compare)
			if !ok {
				continue
			}
			for _, o := range []Operand{cmp.Left, cmp.Right} {
				if pv, ok := o.(PassValue); ok && !slices.Contains(bound, pv.Var) {
					return fmt.Errorf("%s: pass value of var %q outside its iterate", where, pv.Var)
				}
			}
		}
	}
	return nil
}

func checkPredicates(where string, p Predicates) error {
	for d := range p.Text {
		if !slices.Contains(Dialects, d) {
			return fmt.Errorf("%s: predicate dialect %q unknown", where, d)
		}
	}
	return nil
}
