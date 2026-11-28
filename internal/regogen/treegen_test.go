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
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"slices"
	"strings"
	"testing"

	"authz-agent/internal/policyir"
)

// This file builds random policy trees in the shape the PAP exports, renders
// them as the export the agent loads, and transforms them in ways that must not
// change any answer. Tests of the check and of the filter share it.
//
// The PAP writes a simplified set as type SIMPLIFIED with the target
// resourceType == 'doc', DENY_UNLESS_PERMIT on the set and on every policy, a
// policy target operation == 'read' (true for ALL), and ALLOW rules whose
// target is subject.roles CONTAINS ANY 'x','y'. A set of any other shape is
// read as a regular set, so [genTree.export] checks that every simplified set
// loaded as one.

// genCond is a condition: an atom, or the AND or OR of two conditions. The
// condition language has no parentheses, so a condition renders in
// disjunctive normal form.
type genCond struct {
	op   string // "atom", "and", "or"
	atom string
	l, r *genCond
}

func genAtom(text string) *genCond { return &genCond{op: "atom", atom: text} }

func (c *genCond) dnf() [][]string {
	switch c.op {
	case "atom":
		return [][]string{{c.atom}}
	case "or":
		return append(c.l.dnf(), c.r.dnf()...)
	}
	var out [][]string
	for _, a := range c.l.dnf() {
		for _, b := range c.r.dnf() {
			out = append(out, append(append([]string{}, a...), b...))
		}
	}
	return out
}

// text is the condition as the export spells it; "" for none.
func (c *genCond) text() string {
	if c == nil {
		return ""
	}
	var ds []string
	for _, conj := range c.dnf() {
		ds = append(ds, strings.Join(conj, " AND "))
	}
	return strings.Join(ds, " OR ")
}

// genPredicate is an author predicate in each dialect it is written in.
type genPredicate struct {
	name                       string
	rsql, sql, mongo, querydsl string
}

// genPredicates are predicates over the columns a, b, and c, among them an OR
// and one with the subject's id substituted.
var genPredicates = []genPredicate{
	{"a==y", `a=="y"`, `a = 'y'`, `"a": {"$eq": "y"}`, `a.eq("y")`},
	{"a==y or b==y", `a=="y",b=="y"`, `a = 'y' OR b = 'y'`, `{"$or": [{"a": "y"}, {"b": "y"}]}`,
		`a.eq("y").or(b.eq("y"))`},
	{"b!=y", `b!="y"`, `b <> 'y'`, `"b": {"$ne": "y"}`, `b.ne("y")`},
	{"c in x,q", `c=in=("x","q")`, `c IN ('x', 'q')`, `{"c": {"$in": ["x", "q"]}}`, `c.in("x", "q")`},
	{"a==id", `a==${subject.id}`, `a = '${subject.id}'`, `"a": "${subject.id}"`, `a.eq("${subject.id}")`},
}

type genRule struct {
	id, target, effect string
	cond               *genCond
	pred               *genPredicate
}

type genPolicy struct {
	id, target, alg string
	rules           []*genRule
}

type genSet struct {
	id, target, alg string
	simplified      bool
	policies        []*genPolicy
	nested          []*genSet
}

// genTree is the sets of one tenant, t1, of resource type doc.
type genTree struct {
	sets []*genSet
}

// The atoms of conditions and targets: GENERAL PIPs g and h (see
// [generalPIPs]), the built-in subject attributes, the access atoms, and the
// resource column d.
var (
	genSubjectAtoms = []string{"subject.g == 'x'", "subject.g != 'x'", "subject.h == 'x'", "subject.g IS NULL",
		"subject.id == 'y'", "subject.roles CONTAINS 'x'", "subject.h == subject.g",
		"subject allowed 'write' on resource", "subject denied 'write' on resource", "true", "false"}
	genResourceAtoms = []string{"resource.d == 'y'", "resource.d != 'y'", "resource.d IN 'y', 'z'",
		"resource.d IS NULL", "resource.d == subject.h"}
	genAlgorithms = []string{"DENY_OVERRIDES", "PERMIT_OVERRIDES", "DENY_UNLESS_PERMIT", "PERMIT_UNLESS_DENY"}
	genTargets    = []string{"true", "true", "operation == 'read'", "operation == 'write'", "subject.g == 'x'",
		"resource.d == 'y'"}
	genRoleTargets      = []string{"subject.roles CONTAINS ANY 'x'", "subject.roles CONTAINS ANY 'x','y'"}
	genOperationTargets = []string{"operation == 'read'", "operation == 'write'", "true"}
)

// treeGen draws trees from a seeded source; ids are unique within one tree.
type treeGen struct {
	rnd *rand.Rand
	id  int
}

func newTreeGen(seed uint64) *treeGen {
	return &treeGen{rnd: rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15))}
}

func (g *treeGen) next(prefix string) string {
	g.id++
	return fmt.Sprintf("%s%d", prefix, g.id)
}

func pick[T any](g *treeGen, xs []T) T { return xs[g.rnd.IntN(len(xs))] }

func (g *treeGen) atom() *genCond {
	if g.rnd.IntN(3) == 0 {
		return genAtom(pick(g, genResourceAtoms))
	}
	return genAtom(pick(g, genSubjectAtoms))
}

func (g *treeGen) cond() *genCond {
	switch g.rnd.IntN(5) {
	case 0:
		return nil
	case 1, 2:
		return g.atom()
	case 3:
		return &genCond{op: "and", l: g.atom(), r: g.atom()}
	}
	return &genCond{op: "or", l: g.atom(), r: g.atom()}
}

func (g *treeGen) pred() *genPredicate {
	if g.rnd.IntN(2) == 0 {
		return nil
	}
	return &genPredicates[g.rnd.IntN(len(genPredicates))]
}

func (g *treeGen) policy() *genPolicy {
	p := &genPolicy{id: g.next("p"), target: pick(g, genTargets), alg: pick(g, genAlgorithms)}
	for k := g.rnd.IntN(3) + 1; k > 0; k-- {
		p.rules = append(p.rules, &genRule{id: g.next("r"), target: pick(g, genTargets),
			effect: pick(g, []string{"ALLOW", "DENY"}), cond: g.cond(), pred: g.pred()})
	}
	return p
}

func (g *treeGen) simplifiedSet() *genSet {
	s := &genSet{id: g.next("s"), target: "resourceType == 'doc'", alg: "DENY_UNLESS_PERMIT", simplified: true}
	for k := g.rnd.IntN(3) + 1; k > 0; k-- {
		p := &genPolicy{id: g.next("p"), target: pick(g, genOperationTargets), alg: "DENY_UNLESS_PERMIT"}
		for j := g.rnd.IntN(2) + 1; j > 0; j-- {
			p.rules = append(p.rules, &genRule{id: g.next("r"), target: pick(g, genRoleTargets), effect: "ALLOW",
				cond: g.cond(), pred: g.pred()})
		}
		s.policies = append(s.policies, p)
	}
	return s
}

func (g *treeGen) set(depth int) *genSet {
	if depth == 0 && g.rnd.IntN(3) == 0 {
		return g.simplifiedSet()
	}
	s := &genSet{id: g.next("s"), target: "resourceType == 'doc'", alg: pick(g, genAlgorithms)}
	if depth > 0 {
		s.target = pick(g, genTargets)
	}
	for k := g.rnd.IntN(2) + 1; k > 0; k-- {
		s.policies = append(s.policies, g.policy())
	}
	if depth < 1 && g.rnd.IntN(3) == 0 {
		for k := g.rnd.IntN(2) + 1; k > 0; k-- {
			s.nested = append(s.nested, g.set(depth+1))
		}
	}
	return s
}

// tree draws one or two top-level sets.
func (g *treeGen) tree() *genTree {
	t := &genTree{}
	for k := g.rnd.IntN(2) + 1; k > 0; k-- {
		t.sets = append(t.sets, g.set(0))
	}
	return t
}

func genJSON(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		panic(err)
	}
	return string(b)
}

// policySets renders the tree as the policySets document of the export.
func (t *genTree) policySets() string {
	// A rule of a simplified set carries no QueryDSL predicate: with one, the
	// set loads as a regular set.
	rule := func(r *genRule, simplified bool) string {
		var b strings.Builder
		fmt.Fprintf(&b, `{"ruleId": %q, "target": %s, `, r.id, genJSON(r.target))
		if c := r.cond.text(); c != "" {
			fmt.Fprintf(&b, `"condition": %s, `, genJSON(c))
		}
		fmt.Fprintf(&b, `"effect": %q, "tenantId": "t1"`, r.effect)
		if r.pred != nil {
			fmt.Fprintf(&b, `, "rsqlPredicate": %s, "sqlPredicate": %s, "mongodbPredicate": %s`,
				genJSON(r.pred.rsql), genJSON(r.pred.sql), genJSON(r.pred.mongo))
			if !simplified {
				fmt.Fprintf(&b, `, "predicate": %s`, genJSON(r.pred.querydsl))
			}
		}
		b.WriteString("}")
		return b.String()
	}
	policy := func(p *genPolicy, simplified bool) string {
		var rs []string
		for _, r := range p.rules {
			rs = append(rs, rule(r, simplified))
		}
		return fmt.Sprintf(`{"policyId": %q, "target": %s, "combiningAlgorithm": %q, "tenantId": "t1", "rules": [%s]}`,
			p.id, genJSON(p.target), p.alg, strings.Join(rs, ", "))
	}
	var set func(s *genSet) string
	set = func(s *genSet) string {
		var ps, ns []string
		for _, p := range s.policies {
			ps = append(ps, policy(p, s.simplified))
		}
		for _, n := range s.nested {
			ns = append(ns, set(n))
		}
		typ := ""
		if s.simplified {
			typ = `"type": "SIMPLIFIED", `
		}
		nested := ""
		if len(ns) > 0 {
			nested = `"policySets": [` + strings.Join(ns, ", ") + `], `
		}
		return fmt.Sprintf(`{"policySetId": %q, "name": %q, "status": "ACTIVE", %s"target": %s, `+
			`"combiningAlgorithm": %q, "tenantId": "t1", %s"policies": [%s]}`,
			s.id, s.id, typ, genJSON(s.target), s.alg, nested, strings.Join(ps, ", "))
	}
	var out []string
	for _, s := range t.sets {
		out = append(out, set(s))
	}
	return `{"policySets": [` + strings.Join(out, ",\n") + `]}`
}

// export loads the tree as the agent does, with g and h declared as GENERAL
// PIPs. It fails where a set the generator marked simplified was not read as a
// simplified group, since a test of the simplified path would then test the
// regular one.
func (t *genTree) export() (*policyir.Tree, error) {
	pips := `{"pips": [` + strings.ReplaceAll(generalPIPs, `{"name"`, `{"tenantId": "t1", "name"`) + `]}`
	exp, err := policyir.FromRegular([]byte(t.policySets()), []byte(pips))
	if err != nil {
		return nil, err
	}
	tree, ok := exp.Trees["t1"]
	if !ok {
		return nil, fmt.Errorf("no tree of t1: failed %v, dropped %v", exp.Failed, exp.Dropped)
	}
	var loaded []string
	for _, g := range tree.Simplified {
		loaded = append(loaded, g.ID)
	}
	var regular []string
	t.eachSet(func(s *genSet) {
		if s.simplified && !slices.Contains(loaded, s.id) {
			regular = append(regular, s.id)
		}
	})
	if len(regular) > 0 {
		return nil, fmt.Errorf("sets %v of type SIMPLIFIED were read as regular sets", regular)
	}
	return tree, nil
}

// clone copies the tree deeply; conditions and predicates are shared, since
// no transformation edits them in place.
func (t *genTree) clone() *genTree {
	var set func(s *genSet) *genSet
	set = func(s *genSet) *genSet {
		c := *s
		c.policies = nil
		for _, p := range s.policies {
			pc := *p
			pc.rules = nil
			for _, r := range p.rules {
				rc := *r
				pc.rules = append(pc.rules, &rc)
			}
			c.policies = append(c.policies, &pc)
		}
		c.nested = nil
		for _, n := range s.nested {
			c.nested = append(c.nested, set(n))
		}
		return &c
	}
	out := &genTree{}
	for _, s := range t.sets {
		out.sets = append(out.sets, set(s))
	}
	return out
}

// eachSet calls f on every set of the tree, nested ones included.
func (t *genTree) eachSet(f func(*genSet)) {
	var walk func(s *genSet)
	walk = func(s *genSet) {
		f(s)
		for _, n := range s.nested {
			walk(n)
		}
	}
	for _, s := range t.sets {
		walk(s)
	}
}

// swapped is c with the operands of each AND and OR in the order rnd picks.
func (c *genCond) swapped(rnd *rand.Rand) *genCond {
	if c == nil || c.op == "atom" {
		return c
	}
	l, r := c.l.swapped(rnd), c.r.swapped(rnd)
	if rnd.IntN(2) == 0 {
		l, r = r, l
	}
	return &genCond{op: c.op, l: l, r: r}
}

// genRelation is a transformation of a tree that changes no answer of the
// check or the filter.
type genRelation struct {
	name  string
	apply func(t *genTree, rnd *rand.Rand) *genTree
}

func shuffle[T any](rnd *rand.Rand, xs []T) {
	rnd.Shuffle(len(xs), func(i, j int) { xs[i], xs[j] = xs[j], xs[i] })
}

// genRelations are the transformations: every combining algorithm of the
// language is commutative and idempotent, a target that never holds keeps its
// policy out of every answer, and ids name nodes without deciding anything.
var genRelations = []genRelation{
	{"shuffle sets", func(t *genTree, rnd *rand.Rand) *genTree {
		c := t.clone()
		shuffle(rnd, c.sets)
		c.eachSet(func(s *genSet) { shuffle(rnd, s.nested) })
		return c
	}},
	{"shuffle policies", func(t *genTree, rnd *rand.Rand) *genTree {
		c := t.clone()
		c.eachSet(func(s *genSet) { shuffle(rnd, s.policies) })
		return c
	}},
	{"shuffle rules", func(t *genTree, rnd *rand.Rand) *genTree {
		c := t.clone()
		c.eachSet(func(s *genSet) {
			for _, p := range s.policies {
				shuffle(rnd, p.rules)
			}
		})
		return c
	}},
	{"swap operands of AND and OR", func(t *genTree, rnd *rand.Rand) *genTree {
		c := t.clone()
		c.eachSet(func(s *genSet) {
			for _, p := range s.policies {
				for _, r := range p.rules {
					r.cond = r.cond.swapped(rnd)
				}
			}
		})
		return c
	}},
	{"add a policy of no operation first", func(t *genTree, rnd *rand.Rand) *genTree {
		return withPolicyOfNoOperation(t, true)
	}},
	{"add a policy of no operation last", func(t *genTree, rnd *rand.Rand) *genTree {
		return withPolicyOfNoOperation(t, false)
	}},
	{"duplicate a policy", func(t *genTree, rnd *rand.Rand) *genTree {
		c := t.clone()
		var sets []*genSet
		c.eachSet(func(s *genSet) { sets = append(sets, s) })
		s := sets[rnd.IntN(len(sets))]
		p := *s.policies[rnd.IntN(len(s.policies))]
		p.id += "dup"
		var rules []*genRule
		for _, r := range p.rules {
			rc := *r
			rc.id += "dup"
			rules = append(rules, &rc)
		}
		p.rules = rules
		at := rnd.IntN(len(s.policies) + 1)
		s.policies = append(s.policies[:at], append([]*genPolicy{&p}, s.policies[at:]...)...)
		return c
	}},
	{"rename ids", func(t *genTree, rnd *rand.Rand) *genTree {
		c := t.clone()
		c.eachSet(func(s *genSet) {
			s.id = "renamed-" + s.id
			for _, p := range s.policies {
				p.id = "renamed-" + p.id
				for _, r := range p.rules {
					r.id = "renamed-" + r.id
				}
			}
		})
		return c
	}},
}

// withPolicyOfNoOperation adds to every set a policy whose target holds for
// no operation the tests ask about, and whose rules would change the answer
// if it applied: one allows outright and one depends on a PIP.
func withPolicyOfNoOperation(t *genTree, first bool) *genTree {
	c := t.clone()
	n := 0
	c.eachSet(func(s *genSet) {
		n++
		p := &genPolicy{id: fmt.Sprintf("never%d", n), target: "operation == 'none'", alg: "DENY_UNLESS_PERMIT"}
		if s.simplified {
			p.rules = []*genRule{
				{id: p.id + "a", target: genRoleTargets[0], effect: "ALLOW"},
				{id: p.id + "b", target: genRoleTargets[0], effect: "ALLOW", cond: genAtom("subject.g == 'x'")},
			}
		} else {
			p.alg = "PERMIT_OVERRIDES"
			p.rules = []*genRule{
				{id: p.id + "a", target: "true", effect: "ALLOW"},
				{id: p.id + "b", target: "true", effect: "DENY", cond: genAtom("subject.g == 'x'")},
			}
		}
		if first {
			s.policies = append([]*genPolicy{p}, s.policies...)
		} else {
			s.policies = append(s.policies, p)
		}
	})
	return c
}

// A set of type SIMPLIFIED in a shape the agent does not read as simplified
// loads as a regular set, and a test of the simplified path would then test
// the regular one; the generator refuses such a tree and names the set.
func TestTheGeneratorRefusesATreeWhoseSimplifiedSetLoadsAsARegularOne(t *testing.T) {
	read := simplifiedReadSet(&genRule{})
	other := simplifiedReadSet(&genRule{})
	other.id = "other"
	other.policies[0].target = "subject.g == 'x'"
	if _, err := (&genTree{sets: []*genSet{read}}).export(); err != nil {
		t.Fatalf("export of a set in the simplified shape: %v", err)
	}
	_, err := (&genTree{sets: []*genSet{read, other}}).export()
	if err == nil || !strings.Contains(err.Error(), "[other]") {
		t.Errorf("export of a set with a policy target over a PIP = %v, want an error naming the set other", err)
	}
}
