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

package regogen

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"authz-agent/internal/policyir"
	"authz-agent/internal/regogen/spectables"
)

// The module text carries comments that lead a reader from a line back to
// the policy it came from. Every node of the tree has a label: setLabel of
// its set's ID for a top-level set or simplified group (with _dupK for the
// K-th set of a repeated ID), then _sK for the K-th nested set, _pK for the
// K-th policy, and _rK for the K-th rule, counting from 1 within the parent.
// The label also starts the names of the node's rules. A label depends on
// the IDs and positions inside one top-level set alone, so an edit of one set
// leaves the labels and the rule names of the others as they were. The first
// clause that reads a node writes the node's source above it: the IDs, the
// names, the target, and the condition.

// exprSrc is the leaf an expression of a condition came from.
type exprSrc struct {
	// node is the label of the node whose target or condition holds the
	// leaf.
	node string
	// nodes, on a reference to a subject group or to a shared rule, are the
	// labels of the innermost nodes the referenced clauses came from at
	// this reference.
	nodes []string
	// atom is the comparison as policyir.FormatConditionBrief writes it.
	atom string
	// outcome is the outcome of atom that the expression's clause requires:
	// T on the true rail of the comparison, F on the false one, and empty
	// for the atom of a simplified group.
	outcome spectables.Outcome
}

var uuidRE = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// setLabel returns the label of a top-level set or simplified group. For a
// UUID it is set_, the first 8 hex digits, _, and the first 4 hex digits of
// the SHA-256 of the whole ID: hand-made IDs in one tenant often share the
// first 8 digits and differ anywhere after them. For any other ID it is set_
// and the ID with each _ doubled and each character other than a letter or a
// digit written as _<hex code>_, which reads back to the ID.
func setLabel(id string) string {
	if uuidRE.MatchString(id) {
		sum := sha256.Sum256([]byte(id))
		return "set_" + strings.ToLower(id[:8]) + "_" + hex.EncodeToString(sum[:2])
	}
	return "set_" + escapeID(id)
}

// escapeID writes id as an identifier: letters and digits as they are, _ as
// __, and any other character as _ and its hex code and _.
func escapeID(id string) string {
	var b strings.Builder
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '_':
			b.WriteString("__")
		default:
			fmt.Fprintf(&b, "_%x_", r)
		}
	}
	return b.String()
}

// source records the lines that describe the node with label to a reader of
// the module, and the label of its parent, empty for a top-level node.
func (g *gen) source(label, parent string, lines ...string) {
	if _, ok := g.sources[label]; ok {
		return
	}
	g.sources[label] = nodeSource{parent: parent, lines: lines}
}

type nodeSource struct {
	parent string
	lines  []string
}

// condText is a condition as one line of a comment, or (none) without one.
func condText(c *policyir.Condition) string {
	if c == nil {
		return "(none)"
	}
	return policyir.FormatConditionBrief(c)
}

func atomText(a policyir.Atom) string {
	return policyir.FormatConditionBrief(&policyir.Condition{Disjuncts: [][]policyir.Atom{{a}}})
}

// nodeHead is the first line of the source of a set, a policy, or a rule:
// its kind, its ID, its name where it has one, and what follows.
func nodeHead(kind, id, name, tail string) string {
	if name == "" {
		return fmt.Sprintf("%s %q, %s", kind, id, tail)
	}
	return fmt.Sprintf("%s %q %q, %s", kind, id, commentLine(name), tail)
}

// stamp returns d with src on every expression that has no source yet.
func stamp(d dnf, src *exprSrc) dnf {
	if len(d) == 0 {
		return d
	}
	out := make(dnf, len(d))
	for i, c := range d {
		nc := make(clause, len(c))
		for j, e := range c {
			if e.src == nil {
				e.src = src
			}
			nc[j] = e
		}
		out[i] = nc
	}
	return out
}

// clauseNodes returns the labels of the innermost nodes the expressions of c
// came from: a label that another one extends is left out.
func clauseNodes(c clause) []string {
	var labels []string
	for _, e := range c {
		if e.src == nil {
			continue
		}
		for _, l := range append([]string{e.src.node}, e.src.nodes...) {
			if l != "" && !slices.Contains(labels, l) {
				labels = append(labels, l)
			}
		}
	}
	out := labels[:0:0]
	for _, l := range labels {
		if !slices.ContainsFunc(labels, func(o string) bool { return isBelow(o, l) }) {
			out = append(out, l)
		}
	}
	slices.Sort(out)
	return out
}

// isBelow reports whether the node with label o is below the node with label
// l: o extends l by _ and a step _sK, _pK, or _rK. An escaped ID never puts
// s, p, or r after a single _, so a set whose ID extends another's is not
// below it.
func isBelow(o, l string) bool {
	rest, ok := strings.CutPrefix(o, l+"_")
	return ok && len(rest) > 1 && strings.ContainsRune("spr", rune(rest[0])) && rest[1] >= '0' && rest[1] <= '9'
}

// dnfNodes returns the labels of the innermost nodes the clauses of d came
// from.
func dnfNodes(d dnf) []string {
	var all clause
	for _, c := range d {
		all = append(all, c...)
	}
	return clauseNodes(all)
}

// atoms returns the distinct comparisons the expressions of d came from, in
// the order they first appear.
func atoms(d dnf) []string {
	var out []string
	for _, c := range d {
		for _, e := range c {
			if e.src != nil && e.src.atom != "" && !slices.Contains(out, e.src.atom) {
				out = append(out, e.src.atom)
			}
		}
	}
	return out
}

// clauseComment is the comment above a clause of a product several nodes
// read: the innermost nodes the clause came from, then each comparison it
// requires and the outcome it requires of it, as in
// "set_x_p1_r1: subject.roles CONTAINS "A" -> T".
func clauseComment(c clause) string {
	var parts []string
	for _, e := range c {
		if e.src == nil || e.src.atom == "" {
			continue
		}
		p := e.src.atom
		if e.src.outcome != "" {
			p += " -> " + string(e.src.outcome)
		}
		if !slices.Contains(parts, p) {
			parts = append(parts, p)
		}
	}
	line := strings.Join(clauseNodes(c), ", ")
	if len(parts) > 0 && line != "" {
		line += ": "
	}
	return line + strings.Join(parts, "; ")
}

// commentLine makes s fit on one comment line.
func commentLine(s string) string {
	return strings.Map(func(r rune) rune {
		if r < ' ' || r == 0x7f || r == '\u2028' || r == '\u2029' {
			return ' '
		}
		return r
	}, s)
}

// legend opens a module: what the names and the fields of the input mean.
const legend = `# Generated from the policies of one tenant; the comments name the policy
# each line came from.
#
# A node label names a policy set by set_, the first 8 hex digits of its
# UUID, and 4 hex digits of the SHA-256 of the UUID; an ID that is not a UUID
# follows set_ with _ doubled and any character but a letter or a digit as
# _<hex code>_. Then _sK names the K-th nested set, _pK the K-th policy, and
# _rK the K-th rule in it; _dupK marks the K-th set of a repeated ID, and
# _each the set an iterate evaluates once per pass. A comment block with the
# IDs, names, targets, and conditions stands above the first clause read from
# a node, and "# <label>" above each run of clauses from one node.
#
# allow holds where permit holds and failed does not: permit where the
# policies permit, failed where a rule applies whose condition is unknown
# because a value it reads failed, such as a PIP whose call failed or IS EMPTY
# over a null PIP body, which denies the resource whatever the other rules
# give.
#
# Rules: <node>_<b><x>_K holds when bound b (lo, hi) of the node equals x (P
# permit, D deny), and <node>_loE_K where failed holds at or below the node;
# <node>_in_<b><x>_K when its children combine to x, and
# <node>_any_<b><x> when some child of the node has bound b equal to x; for
# an iterate, <node>_pass_<b><x>(p) is that bound in pass p.
# dec_<operation>_<depth>_<b><x> is that bound of the decision for another
# operation (subject allowed or denied), read from a copy of the tree whose
# nodes are named dec_<operation>_<depth>_<label>. and_<hash> holds a factor
# of an AND that is not multiplied out into the clauses, rail_t_<hash> and
# rail_f_<hash> the clauses where a condition is true and where it is false (a
# rule reads them negated), and g_<hash> in input.subject_groups a subject
# group; <hash> is the first 12 hex digits of the SHA-256 of what they hold,
# so any node may read them. <rule>__body holds the clauses of a long rule.
#
# input.<field>[<operand>] is a field of the value record of an operand,
# keyed by the operand as a policy writes it: state, class, key, value_key,
# match_key, element_keys and element_own_keys the match and the own tokens
# of the elements, text, segments, segments_from_end, and segment_count the
# path segments from the start, from the end, and their count, has_null
# whether a list holds null, text_key the key of the text a string equals a
# list or an object by, equality_key the key two lists or objects are equal
# by, length, element_tokens the own tokens of the elements and
# element_tokens_with_text their match tokens and the token of the text of a
# list or an object element, number the key < and > compare a number by, a
# list that sorts as the numbers do, subset_left and subset_right the tokens
# IS SUBSET reads on the left and on the right, beyond_double the text
# Infinity or -Infinity of a number beyond the range of a double, which MATCH
# reads.
# Two scalars are equal when the own tokens of one meet the match tokens of
# the other. key is the folded text of a string or a boolean and N<value> of
# a number, and is both an own and a match token; value_key, an own token of
# a string, is S<value> where BigDecimal reads the string and a bare S
# otherwise; match_key is S<value> of a number and N<value> of a string that
# BigDecimal reads. A token of element_tokens is a key with its kind: t: a
# scalar by one of its own or match tokens, o: object, l:[...] list, and
# inside a nested list n: a number by its value, c: a string with its case,
# and t: a boolean. In the tokens of IS SUBSET, t: is a string or a boolean
# by its text with case, and on the right also a list by its Java text; s: a
# list or an object on the left by its Java text and a string on the right;
# b: a boolean; n: a number by its value, also a string that BigDecimal reads
# on the right; and m: a string that BigDecimal reads on the left and a
# number on the right, by its value.
# A class is string, scalar (a number or a boolean), list, pip_list (a list
# of several values a HEADER, GENERAL, or FILTERED PIP builds),
# list_with_null, nested_list (a list with a list or an object element),
# object, or null. input.folded_roles holds the folded roles,
# input.subject_groups the subject groups the request is in, input.m2m
# whether the subject is machine-to-machine, input.scope_passes the passes of
# an iterate over the permission scope, and input.scope_failed whether
# reading the scope failed.
#
# A comment above rail_t_<hash> or rail_f_<hash> names the condition; a
# comment above each clause of and_<hash> names the nodes it came from and the
# outcome it requires of each comparison.
`

// commenter writes the comments above the clauses of one module text.
type commenter struct {
	g       *gen
	b       *strings.Builder
	printed map[string]bool
	// last is the label comment written above the previous clause, so a
	// run of clauses from one node gets it once.
	last string
}

// clause writes, above clause c, the source of every node c came from that
// no earlier clause wrote, and the labels of those nodes when they differ
// from the previous clause's.
func (cm *commenter) clause(c clause) {
	labels := clauseNodes(c)
	if len(labels) == 0 {
		return
	}
	for _, l := range labels {
		cm.source(l)
	}
	line := "# " + strings.Join(labels, ", ")
	if line != cm.last {
		cm.b.WriteString(line + "\n")
		cm.last = line
	}
}

// source writes the source of the node with label, after its parent's.
func (cm *commenter) source(label string) {
	if cm.printed[label] {
		return
	}
	cm.printed[label] = true
	src, ok := cm.g.sources[label]
	if !ok {
		return
	}
	if src.parent != "" {
		cm.source(src.parent)
	}
	cm.b.WriteString("# " + label + ": " + commentLine(src.lines[0]) + "\n")
	for _, l := range src.lines[1:] {
		cm.b.WriteString("#   " + commentLine(l) + "\n")
	}
	cm.last = ""
}
