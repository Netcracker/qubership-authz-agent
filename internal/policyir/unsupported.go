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
	"errors"
	"fmt"
	"slices"
)

// Form names a form of the language the agent cannot execute yet: one the
// legacy service executes, or one the specification does not model.
type Form string

// The forms the agent cannot execute yet. A frontend writes FormJSONPath and
// FormSyntax as an [Unsupported] atom or operand; [Tree.Unsupported] finds
// FormNestedIterate from the shape of the tree and FormPIPExtension from
// [PIP.Unsupported].
const (
	// FormJSONPath is a resource path that package jsonpath does not compile.
	FormJSONPath Form = "jsonpath"
	// FormSyntax is condition text of an export that the agent's parser
	// refuses. The PAP refuses such text too, so its presence means the two
	// parsers disagree.
	FormSyntax Form = "syntax"
	// FormNestedIterate is a set with iterate inside a set with iterate.
	FormNestedIterate Form = "nested-iterate"
	// FormPIPExtension is a PIP declaration with fields of an extension the
	// legacy service does not have.
	FormPIPExtension Form = "pip-extension"
)

var forms = []Form{FormJSONPath, FormSyntax, FormNestedIterate, FormPIPExtension}

// Unsupported stands for an atom or an operand the agent cannot execute yet.
// Text is the source text of the form, so the report can quote it.
type Unsupported struct {
	Form Form
	Text string
}

func validateUnsupported(u Unsupported) error {
	if !slices.Contains(forms, u.Form) {
		return fmt.Errorf("unsupported: form %q unknown", u.Form)
	}
	if u.Text == "" {
		return errors.New("unsupported: no source text")
	}
	return nil
}

// Finding is one form of a [Tree] the agent cannot execute yet.
type Finding struct {
	// Where is the path of the node in the tree, such as
	// `set "s1" > policy "p1" > rule "r1" > condition`. A node whose ID a
	// sibling shares also carries its position: `set "s1" #0`.
	Where string
	Form  Form
	Text  string
}

// Unsupported lists every form of the tree the agent cannot execute yet: the
// PIP declarations first, then the simplified groups and the sets in tree
// order. A tree with an empty list can be generated in full; a generator
// rejects any other tree as a whole.
func (t *Tree) Unsupported() []Finding {
	var out []Finding
	for _, p := range t.PIPs {
		if p.Unsupported != "" {
			out = append(out, Finding{Where: fmt.Sprintf("pip %q", p.Name), Form: FormPIPExtension, Text: p.Unsupported})
		}
	}
	cond := func(where *node, c *Condition) {
		if c == nil {
			return
		}
		for _, d := range c.Disjuncts {
			for _, a := range d {
				switch v := a.(type) {
				case Unsupported:
					out = append(out, Finding{Where: where.String(), Form: v.Form, Text: v.Text})
				case Compare:
					for _, o := range []Operand{v.Left, v.Right} {
						if u, ok := o.(Unsupported); ok {
							out = append(out, Finding{Where: where.String(), Form: u.Form, Text: u.Text})
						}
					}
				}
			}
		}
	}
	groups := labels(t.Simplified, groupLabel)
	for i, g := range t.Simplified {
		group := (*node)(nil).child(groups[i])
		policies := labels(g.Policies, simplifiedPolicyLabel)
		for j, p := range g.Policies {
			cond(group.child(policies[j]).child("condition"), p.Condition)
		}
	}
	var set func(here *node, s *PolicySet, iterating bool)
	set = func(here *node, s *PolicySet, iterating bool) {
		if s.Iterate != nil && iterating {
			out = append(out, Finding{Where: here.String(), Form: FormNestedIterate, Text: "iterate var " + s.Iterate.Var})
		}
		cond(here.child("target"), s.Target)
		policies := labels(s.Policies, policyLabel)
		for i, p := range s.Policies {
			pp := here.child(policies[i])
			cond(pp.child("target"), p.Target)
			rules := labels(p.Rules, ruleLabel)
			for j, r := range p.Rules {
				rp := pp.child(rules[j])
				cond(rp.child("target"), r.Target)
				cond(rp.child("condition"), r.Condition)
			}
		}
		children := labels(s.Sets, setLabel)
		for i, c := range s.Sets {
			set(here.child(children[i]), c, iterating || s.Iterate != nil)
		}
	}
	top := labels(t.Sets, setLabel)
	for i, s := range t.Sets {
		set((*node)(nil).child(top[i]), s, false)
	}
	return out
}

// labels names each of the sibling nodes by label, and adds the position of a
// node whose label another sibling shares, so a path names one node.
func labels[T any](nodes []T, label func(T) string) []string {
	out := make([]string, len(nodes))
	seen := map[string]int{}
	for i, n := range nodes {
		out[i] = label(n)
		seen[out[i]]++
	}
	for i, l := range out {
		if seen[l] > 1 {
			out[i] = fmt.Sprintf("%s #%d", l, i)
		}
	}
	return out
}

func groupLabel(g *SimplifiedGroup) string {
	return fmt.Sprintf("simplified %q/%q/%q", g.Domain, g.Component, g.ResourceType)
}

func simplifiedPolicyLabel(p *SimplifiedPolicy) string { return fmt.Sprintf("policy %q", p.ID) }
func setLabel(s *PolicySet) string                     { return fmt.Sprintf("set %q", s.ID) }
func policyLabel(p *Policy) string                     { return fmt.Sprintf("policy %q", p.ID) }
func ruleLabel(r *Rule) string                         { return fmt.Sprintf("rule %q", r.ID) }
