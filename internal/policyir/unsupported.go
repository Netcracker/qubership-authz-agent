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

// The forms the agent cannot execute yet. A frontend writes every form except
// FormNestedIterate and FormPIPExtension as an [Unsupported] atom or operand;
// [Tree.Unsupported] finds FormNestedIterate from the shape of the tree and
// FormPIPExtension from [PIP.Unsupported].
const (
	// FormJSONPath is a resource path that package jsonpath does not compile.
	FormJSONPath Form = "jsonpath"
	// FormOperand is an operand of a kind the specification does not evaluate.
	FormOperand Form = "operand"
	// FormPIPType is a reference to a PIP whose pipType the specification does
	// not evaluate in a condition.
	FormPIPType Form = "pip-type"
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

var forms = []Form{
	FormJSONPath, FormOperand, FormPIPType, FormSyntax, FormNestedIterate, FormPIPExtension,
}

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
	// `set "s1" > policy "p1" > rule "r1" > condition`.
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
	cond := func(where string, c *Condition) {
		if c == nil {
			return
		}
		for _, d := range c.Disjuncts {
			for _, a := range d {
				switch v := a.(type) {
				case Unsupported:
					out = append(out, Finding{Where: where, Form: v.Form, Text: v.Text})
				case Compare:
					for _, o := range []Operand{v.Left, v.Right} {
						if u, ok := o.(Unsupported); ok {
							out = append(out, Finding{Where: where, Form: u.Form, Text: u.Text})
						}
					}
				}
			}
		}
	}
	for _, g := range t.Simplified {
		for _, p := range g.Policies {
			cond(simplifiedPath(g, p)+" > condition", p.Condition)
		}
	}
	var set func(parent string, s *PolicySet, iterating bool)
	set = func(parent string, s *PolicySet, iterating bool) {
		here := join(parent, fmt.Sprintf("set %q", s.ID))
		if s.Iterate != nil && iterating {
			out = append(out, Finding{Where: here, Form: FormNestedIterate, Text: "iterate var " + s.Iterate.Var})
		}
		cond(here+" > target", s.Target)
		for _, p := range s.Policies {
			pp := join(here, fmt.Sprintf("policy %q", p.ID))
			cond(pp+" > target", p.Target)
			for _, r := range p.Rules {
				rp := join(pp, fmt.Sprintf("rule %q", r.ID))
				cond(rp+" > target", r.Target)
				cond(rp+" > condition", r.Condition)
			}
		}
		for _, c := range s.Sets {
			set(here, c, iterating || s.Iterate != nil)
		}
	}
	for _, s := range t.Sets {
		set("", s, false)
	}
	return out
}

func join(parent, node string) string {
	if parent == "" {
		return node
	}
	return parent + " > " + node
}

func simplifiedPath(g *SimplifiedGroup, p *SimplifiedPolicy) string {
	return fmt.Sprintf("simplified %q/%q/%q > policy %q", g.Domain, g.Component, g.ResourceType, p.ID)
}
