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
// [PIP.Unsupported]. A generator also rejects with FormJSONPath a condition
// that reads a PIP whose jsonPath it does not compile.
const (
	// FormJSONPath is a resource path, or the jsonPath of a PIP a condition
	// reads, that package jsonpath does not compile.
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
	t.walk(func(where *node, c *Condition) {
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
	}, func(where *node, s *PolicySet) {
		out = append(out, Finding{Where: where.String(), Form: FormNestedIterate, Text: "iterate var " + s.Iterate.Var})
	}, nil)
	return out
}

// WarningKind names why the agent evaluates a part of a tree otherwise than
// its author likely meant.
type WarningKind string

const (
	// WarnIsM2MComparison is a comparison over subject.isM2M. The agent reads
	// subject.isM2M as absent whatever the token, where the condition
	// subject.isM2M alone tests the M2M token.
	WarnIsM2MComparison WarningKind = "is-m2m-comparison"
	// WarnNoEffect is a rule with no effect, which counts as NOT_APPLICABLE
	// and neither permits nor denies.
	WarnNoEffect WarningKind = "no-effect"
)

// Warning is a part of a [Tree] that the agent evaluates otherwise than its
// author likely meant. A Warning is comparable; two loads of an export
// compare their warnings by [Warning.Identity].
type Warning struct {
	// Where is the path of the node, as in [Finding].
	Where string
	// node is Where without the positions of the siblings that share an ID.
	node string
	Kind WarningKind
	// Atom is the comparison of a WarnIsM2MComparison, empty for the other
	// kinds.
	Atom string
}

// String names the node of w and what the agent does with it.
func (w Warning) String() string {
	switch w.Kind {
	case WarnIsM2MComparison:
		return fmt.Sprintf("%s: %s reads subject.isM2M as absent whatever the token; "+
			"the condition subject.isM2M alone tests whether the token is M2M", w.Where, w.Atom)
	case WarnNoEffect:
		return w.Where + ": names no effect, so the rule counts as NOT_APPLICABLE and neither permits nor denies"
	}
	return fmt.Sprintf("%s: %s", w.Where, w.Kind)
}

// Identity returns w with the positions of its path left out. A sibling of
// the same ID inserted ahead of the node changes those positions and nothing
// else. Siblings that share an ID and a warning have one identity, so a
// caller that compares two loads counts the identities of each.
func (w Warning) Identity() Warning {
	w.Where = w.node
	return w
}

func warning(where *node, kind WarningKind, atom string) Warning {
	return Warning{Where: where.String(), node: where.path(false), Kind: kind, Atom: atom}
}

// Warnings lists, in tree order, the parts of the tree the agent evaluates
// otherwise than their author likely meant: one [WarnIsM2MComparison] for
// each comparison over subject.isM2M and one [WarnNoEffect] for each rule
// with no effect.
func (t *Tree) Warnings() []Warning {
	var out []Warning
	t.walk(func(where *node, c *Condition) {
		for _, d := range c.Disjuncts {
			for _, a := range d {
				cmp, ok := a.(Compare)
				if !ok || cmp.Left != Operand(Subject{Attr: SubjectIsM2M}) && cmp.Right != Operand(Subject{Attr: SubjectIsM2M}) {
					continue
				}
				out = append(out, warning(where, WarnIsM2MComparison, formatAtom(cmp, false)))
			}
		}
	}, nil, func(where *node, r *Rule) {
		if r.Effect == EffectAbsent {
			out = append(out, warning(where, WarnNoEffect, ""))
		}
	})
	return out
}

// walk calls cond for every condition of the tree with its place: the
// conditions of the simplified groups, then those of the sets in tree order.
// It calls nested, where nested is not nil, for every set with iterate inside
// a set with iterate, and rule, where rule is not nil, for every rule of a
// set, after the conditions of the rule.
func (t *Tree) walk(cond func(where *node, c *Condition), nested func(where *node, s *PolicySet),
	rule func(where *node, r *Rule)) {
	visit := func(where *node, c *Condition) {
		if c != nil {
			cond(where, c)
		}
	}
	groups := labels(t.Simplified, groupLabel)
	for i, g := range t.Simplified {
		group := (*node)(nil).at(groups[i])
		policies := labels(g.Policies, simplifiedPolicyLabel)
		for j, p := range g.Policies {
			visit(group.at(policies[j]).child("condition"), p.Condition)
		}
	}
	var set func(here *node, s *PolicySet, iterating bool)
	set = func(here *node, s *PolicySet, iterating bool) {
		if s.Iterate != nil && iterating && nested != nil {
			nested(here, s)
		}
		visit(here.child("target"), s.Target)
		policies := labels(s.Policies, policyLabel)
		for i, p := range s.Policies {
			pp := here.at(policies[i])
			visit(pp.child("target"), p.Target)
			rules := labels(p.Rules, ruleLabel)
			for j, r := range p.Rules {
				rp := pp.at(rules[j])
				visit(rp.child("target"), r.Target)
				visit(rp.child("condition"), r.Condition)
				if rule != nil {
					rule(rp, r)
				}
			}
		}
		children := labels(s.Sets, setLabel)
		for i, c := range s.Sets {
			set(here.at(children[i]), c, iterating || s.Iterate != nil)
		}
	}
	top := labels(t.Sets, setLabel)
	for i, s := range t.Sets {
		set((*node)(nil).at(top[i]), s, false)
	}
}

// EachPredicates calls f with the filter predicates of every simplified
// policy and every rule of the tree, with the path [Tree.Unsupported] gives
// the node and "predicate" after it, in the order of [Tree.Unsupported].
func (t *Tree) EachPredicates(f func(where string, p Predicates)) {
	groups := labels(t.Simplified, groupLabel)
	for i, g := range t.Simplified {
		group := (*node)(nil).at(groups[i])
		policies := labels(g.Policies, simplifiedPolicyLabel)
		for j, p := range g.Policies {
			f(group.at(policies[j]).child("predicate").String(), p.Predicates)
		}
	}
	var set func(here *node, s *PolicySet)
	set = func(here *node, s *PolicySet) {
		policies := labels(s.Policies, policyLabel)
		for i, p := range s.Policies {
			pp := here.at(policies[i])
			rules := labels(p.Rules, ruleLabel)
			for j, r := range p.Rules {
				f(pp.at(rules[j]).child("predicate").String(), r.Predicates)
			}
		}
		children := labels(s.Sets, setLabel)
		for i, c := range s.Sets {
			set(here.at(children[i]), c)
		}
	}
	top := labels(t.Sets, setLabel)
	for i, s := range t.Sets {
		set((*node)(nil).at(top[i]), s)
	}
}

// sibling is a node of the tree among the nodes of its parent: its label,
// and its position among them where another of them shares the label, or -1.
type sibling struct {
	label string
	pos   int
}

// String returns the label, followed by " #" and the position where s has
// one, such as `set "s" #0`.
func (s sibling) String() string {
	if s.pos < 0 {
		return s.label
	}
	return fmt.Sprintf("%s #%d", s.label, s.pos)
}

// labels names each of the sibling nodes by label, and gives the position of
// a node whose label another sibling shares, so a path names one node.
func labels[T any](nodes []T, label func(T) string) []sibling {
	out := make([]sibling, len(nodes))
	seen := map[string]int{}
	for i, n := range nodes {
		out[i] = sibling{label: label(n), pos: -1}
		seen[out[i].label]++
	}
	for i := range out {
		if seen[out[i].label] > 1 {
			out[i].pos = i
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
