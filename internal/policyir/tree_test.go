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
	"strings"
	"testing"
)

// one returns a condition at place with a single conjunction of atoms.
func one(place Place, atoms ...Atom) *Condition {
	return &Condition{Place: place, Disjuncts: [][]Atom{atoms}}
}

var readOp = Compare{Op: OpEQ, Left: Operation{}, Right: String{Value: "READ"}}

// parts is a valid tree before NewTree: one PIP, one simplified group, and a
// top-level set "s1" with iterate var "v" over a policy "p1" with rule "r1" and
// a nested set "s2". A case changes one node and expects NewTree to name it.
type parts struct {
	simplified []*SimplifiedGroup
	sets       []*PolicySet
	pips       []*PIP
}

func validParts() parts {
	return parts{
		pips: []*PIP{{Name: "subject.region", Type: PIPGeneral}},
		simplified: []*SimplifiedGroup{{
			Domain: "d", Component: "c", ResourceType: "uri",
			Policies: []*SimplifiedPolicy{{ID: "sp1", Condition: one(PlaceSimplified, readOp)}},
		}},
		sets: []*PolicySet{{
			ID:        "s1",
			Algorithm: AlgorithmDenyOverrides,
			Target:    one(PlaceSetTarget, readOp),
			Iterate:   &Iterate{Var: "v", Algorithm: AlgorithmPermitOverrides},
			Policies: []*Policy{{
				ID:     "p1",
				Target: one(PlacePolicyTarget, readOp),
				Rules: []*Rule{{
					ID: "r1", Effect: EffectAllow,
					Target:     one(PlaceRuleTarget, readOp),
					Condition:  one(PlaceRuleCondition, Compare{Op: OpEQ, Left: PassValue{Var: "v", Key: "region"}, Right: String{Value: "eu"}}),
					Predicates: Predicates{Text: map[Dialect]string{DialectRSQL: "region==eu"}},
				}},
			}},
			Sets: []*PolicySet{{ID: "s2", Target: one(PlaceSetTarget, Compare{Op: OpIsNotNull, Left: PassValue{Var: "v"}})}},
		}},
	}
}

func (p *parts) rule() *Rule { return p.sets[0].Policies[0].Rules[0] }

func TestNewTreeAcceptsAValidTree(t *testing.T) {
	t.Parallel()

	p := validParts()
	if _, err := NewTree(p.simplified, p.sets, p.pips); err != nil {
		t.Fatalf("NewTree(validParts()): %v", err)
	}
}

func TestNewTreeRejects(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		change    func(p *parts)
		wantWhere string
	}{
		{"a set target at the rule target place", func(p *parts) { p.sets[0].Target.Place = PlaceRuleTarget },
			`set "s1" > target`},
		{"a policy target at the set target place", func(p *parts) { p.sets[0].Policies[0].Target.Place = PlaceSetTarget },
			`set "s1" > policy "p1" > target`},
		{"a rule target at the rule condition place", func(p *parts) { p.rule().Target.Place = PlaceRuleCondition },
			`rule "r1" > target`},
		{"a rule condition at the simplified place", func(p *parts) { p.rule().Condition.Place = PlaceSimplified },
			`rule "r1" > condition`},
		{"a simplified condition at the rule condition place", func(p *parts) {
			p.simplified[0].Policies[0].Condition.Place = PlaceRuleCondition
		}, `simplified "d"/"c"/"uri" > policy "sp1" > condition`},
		{"a pass value in a set beside the iterating one", func(p *parts) {
			p.sets = append(p.sets, &PolicySet{ID: "s3", Target: one(PlaceSetTarget, Compare{Op: OpIsNull, Left: PassValue{Var: "v"}})})
		}, `set "s3" > target`},
		{"a pass value of a var nothing binds", func(p *parts) {
			p.rule().Condition = one(PlaceRuleCondition, Compare{Op: OpIsNull, Left: PassValue{Var: "w"}})
		}, `rule "r1" > condition`},
		{"an iterate var bound twice", func(p *parts) {
			p.sets[0].Sets[0].Iterate = &Iterate{Var: "v", Algorithm: AlgorithmDenyOverrides}
		}, `set "s2"`},
		{"an iterate with no algorithm", func(p *parts) { p.sets[0].Iterate.Algorithm = AlgorithmAbsent }, `set "s1"`},
		{"an iterate with no var", func(p *parts) { p.sets[0].Iterate.Var = "" }, `set "s1"`},
		{"an unknown set algorithm", func(p *parts) { p.sets[0].Algorithm = "FIRST_APPLICABLE" }, `set "s1"`},
		{"an unknown policy algorithm", func(p *parts) { p.sets[0].Policies[0].Algorithm = "FIRST_APPLICABLE" },
			`policy "p1"`},
		{"an unknown effect", func(p *parts) { p.rule().Effect = "PERMIT" }, `rule "r1"`},
		{"an unknown dialect", func(p *parts) { p.rule().Predicates.Text["clang"] = "x" }, `rule "r1"`},
		{"a set that always fails with a policy", func(p *parts) {
			p.sets[0].Sets[0].AlwaysFails = "foreach"
			p.sets[0].Sets[0].Policies = []*Policy{{ID: "p9"}}
		}, `set "s2"`},
		{"a set that always fails with an iterate", func(p *parts) { p.sets[0].AlwaysFails = "foreach" }, `set "s1"`},
		{"a comparison with a list on the left", func(p *parts) {
			p.rule().Condition = one(PlaceRuleCondition, Compare{Op: OpEQ, Left: List{Items: []Literal{String{Value: "a"}}}, Right: Null{}})
		}, `rule "r1" > condition`},
		{"a pass value in a simplified condition", func(p *parts) {
			p.simplified[0].Policies[0].Condition = one(PlaceSimplified, Compare{Op: OpIsNull, Left: PassValue{Var: "v"}})
		}, `simplified "d"/"c"/"uri" > policy "sp1" > condition`},
		{"an iterate with an unknown algorithm", func(p *parts) { p.sets[0].Iterate.Algorithm = "FIRST_APPLICABLE" }, `set "s1"`},
		{"an unknown dialect on a simplified policy", func(p *parts) {
			p.simplified[0].Policies[0].Predicates.Text = map[Dialect]string{"clang": "x"}
		}, `simplified "d"/"c"/"uri" > policy "sp1"`},
		{"a nil top-level set", func(p *parts) { p.sets = append(p.sets, nil) }, `set 1`},
		{"a nil simplified group", func(p *parts) { p.simplified = append(p.simplified, nil) }, `simplified group 1`},
		{"a nil simplified policy", func(p *parts) { p.simplified[0].Policies = append(p.simplified[0].Policies, nil) },
			`simplified "d"/"c"/"uri"`},
		{"a nil PIP", func(p *parts) { p.pips = append(p.pips, nil) }, `pip 1`},
		{"a nil policy", func(p *parts) { p.sets[0].Policies = append(p.sets[0].Policies, nil) }, `set "s1"`},
		{"a nil nested set", func(p *parts) { p.sets[0].Sets = append(p.sets[0].Sets, nil) }, `set "s1"`},
		{"a nil rule", func(p *parts) { p.sets[0].Policies[0].Rules = append(p.sets[0].Policies[0].Rules, nil) },
			`policy "p1"`},
		{"a PIP named without subject.", func(p *parts) { p.pips[0].Name = "region" }, `pip "region"`},
		{"a PIP declared twice", func(p *parts) { p.pips = append(p.pips, &PIP{Name: "subject.region", Type: PIPToken}) },
			`pip "subject.region"`},
		{"an unknown PIP type", func(p *parts) { p.pips[0].Type = "REGO" }, `pip "subject.region"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := validParts()
			tc.change(&p)
			_, err := NewTree(p.simplified, p.sets, p.pips)
			if err == nil {
				t.Fatalf("NewTree() error = nil, want an error naming %s", tc.wantWhere)
			}
			if !strings.Contains(err.Error(), tc.wantWhere) {
				t.Errorf("NewTree() error = %q, want it to name %s", err, tc.wantWhere)
			}
		})
	}
}

func TestTreePIPReportsAMissingDeclaration(t *testing.T) {
	t.Parallel()

	p := validParts()
	tree, err := NewTree(p.simplified, p.sets, p.pips)
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := tree.PIP("subject.region"); !ok || got.Type != PIPGeneral {
		t.Errorf(`PIP("subject.region") = %v, %t, want the GENERAL declaration, true`, got, ok)
	}
	if got, ok := tree.PIP("subject.tier"); ok {
		t.Errorf(`PIP("subject.tier") = %v, true, want nil, false`, got)
	}
}
