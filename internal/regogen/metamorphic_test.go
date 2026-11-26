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
	"context"
	"fmt"
	"maps"
	"math/rand/v2"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/open-policy-agent/opa/v1/rego"

	"authz-agent/internal/policyir"
)

// metamorphicKnown lists the relations the agent breaks today, by case: a
// named tree or a generated one, then the relation. A listed case is logged; a
// listed case that holds fails the test until its entry is removed, and an
// unlisted one fails it. A generated tree is named by its index under the
// default seed, so a change to the generator renumbers them, and its entries
// are found again by a run with this map empty.
var metamorphicKnown = map[string]string{
	"named/an unconditional simplified policy before one over a PIP/reverse":                           f76,
	"named/an unconditional simplified policy before one over a PIP/shuffle policies":                  f76,
	"named/an unconditional simplified policy before one over a PIP and the resource/reverse":          f76,
	"named/an unconditional simplified policy before one over a PIP and the resource/shuffle policies": f76,
	"generated/53/reverse":          f76,
	"generated/60/reverse":          f76,
	"generated/60/shuffle policies": f76,
	"generated/60/shuffle rules":    f76,
}

const f76 = "F76: a simplified policy that allows every row ends the walk of check/filter, so the veto of a " +
	"later simplified policy of the same operation over a failed source is lost, and the filter answer " +
	"depends on the order of the policies"

// metamorphicSubjects are the subjects every tree is asked about: g holds x,
// holds y, failed, or is null; h holds x or failed; the roles are x, which
// the role targets of simplified rules name, z, which none names, or failed.
func metamorphicSubjects(t *testing.T) []mmSubject {
	t.Helper()
	type state struct {
		st, v string
		roles []string
	}
	var out []mmSubject
	for _, g := range []state{{"VALUE", `"x"`, nil}, {"VALUE", `"y"`, nil}, {"ERROR", "", nil},
		{"PIP_NULL", "", nil}} {
		for _, h := range []state{{"VALUE", `"x"`, nil}, {"ERROR", "", nil}} {
			for _, ro := range []state{{"VALUE", `["x"]`, []string{"x"}}, {"VALUE", `["z"]`, []string{"z"}},
				{"ERROR", "", nil}} {
				s := mmSubject{
					name: fmt.Sprintf("g=%s%s h=%s%s roles=%s%s", g.st, g.v, h.st, h.v, ro.st, ro.v),
					values: map[string]Resolved{
						`["subj","g"]`: resolved(t, g.st, g.v), `["subj","h"]`: resolved(t, h.st, h.v),
						`["subj","id"]`: resolved(t, "VALUE", `"y"`), `["subj","roles"]`: resolved(t, ro.st, ro.v),
					},
					roles: ro.roles,
				}
				out = append(out, s)
			}
		}
	}
	return out
}

type mmSubject struct {
	name   string
	roles  []string
	values map[string]Resolved
}

// metamorphicRows are the values of the resource column d that check/resource
// is asked about.
var metamorphicRows = []struct{ name, st, v string }{
	{"d=y", "VALUE", `"y"`}, {"d=z", "VALUE", `"z"`}, {"d absent", "ABSENT", ""},
}

// filterDialects are the dialects whose text a filter answer is compared in.
var filterDialects = []policyir.Dialect{policyir.DialectRSQL, policyir.DialectSQL, policyir.DialectMongoDB,
	policyir.DialectQueryDSL}

// mmAnswers holds what a tree answers to every subject: check/resource for
// read on each row, and check/filter for read.
type mmAnswers struct {
	check  []bool
	filter []FilterAnswer
}

// metamorphicAnswers generates both modules of the tree and asks them; the
// error is a refusal to generate. A tree the loader refuses, or loads in
// another shape than the generator meant, fails the test.
func metamorphicAnswers(t *testing.T, tr *genTree, subjects []mmSubject) (*mmAnswers, error) {
	t.Helper()
	tree, err := tr.export()
	if err != nil {
		t.Fatalf("export: %v\n%s", err, tr.policySets())
	}
	check, err := Generate(tree, table(t), DefaultOptions())
	if err != nil {
		return nil, fmt.Errorf("Generate: %w", err)
	}
	filter, err := GenerateFilter(tree, table(t), DefaultOptions())
	if err != nil {
		return nil, fmt.Errorf("GenerateFilter: %w", err)
	}
	fq, cq := prepareFilter(t, filter), prepareAllow(t, check)
	out := &mmAnswers{}
	for _, s := range subjects {
		for _, r := range metamorphicRows {
			values := map[string]Resolved{`["res",".d"]`: resolved(t, r.st, r.v)}
			for k, v := range s.values {
				values[k] = v
			}
			out.check = append(out.check, evalAllow(t, check, cq, Request{Body: Body{Operation: "read",
				ResourceType: "doc"}, Values: values, Roles: s.roles}))
		}
		req := Request{Body: Body{Operation: "read", ResourceType: "doc"}, Values: s.values, Roles: s.roles}
		out.filter = append(out.filter, evalFilter(t, filter, fq, req))
	}
	return out, nil
}

// prepareFilter compiles the module of check/filter.
func prepareFilter(t *testing.T, m *Module) rego.PreparedEvalQuery {
	t.Helper()
	pq, err := rego.New(append([]func(*rego.Rego){rego.Query(FilterQuery(DefaultOptions().Package)),
		rego.Module("filter.rego", m.Text)}, Builtins()...)...).PrepareForEval(context.Background())
	if err != nil {
		t.Fatalf("PrepareForEval: %v\n%s", err, m.Text)
	}
	return pq
}

// evalFilter answers check/filter for req as the agent does: the module
// gives the statuses, and [Module.Filter] turns them into text.
func evalFilter(t *testing.T, m *Module, pq rego.PreparedEvalQuery, req Request) FilterAnswer {
	t.Helper()
	in, err := Project(m, req)
	if err != nil {
		t.Fatalf("Project: %v", err)
	}
	ctx := replayContext(t, in)
	rs, err := pq.Eval(in.Context(ctx), rego.EvalParsedInput(in.Value()))
	if err != nil {
		t.Fatalf("Eval: %v", err)
	}
	st, err := ReadStatuses(rs[0].Expressions[0].Value)
	if err != nil {
		t.Fatalf("ReadStatuses: %v", err)
	}
	fa, err := m.Filter(ctx, st, &req)
	if err != nil {
		t.Fatalf("Filter: %v", err)
	}
	return fa
}

// metamorphicDiff describes the first answer in which a and b differ, or
// returns "" where they agree. Filter texts agree where their formulas have the
// same truth table ([sameFormula]).
func metamorphicDiff(subjects []mmSubject, a, b *mmAnswers) string {
	for i, s := range subjects {
		for j, r := range metamorphicRows {
			k := i*len(metamorphicRows) + j
			if a.check[k] != b.check[k] {
				return fmt.Sprintf("check/resource for %s, %s: allow %v, then %v", s.name, r.name, a.check[k], b.check[k])
			}
		}
		fa, fb := a.filter[i], b.filter[i]
		for _, d := range filterDialects {
			xa, oka, erra := answerFormula(fa, d)
			xb, okb, errb := answerFormula(fb, d)
			switch {
			case erra != nil || errb != nil:
				return fmt.Sprintf("check/filter for %s in %s: unreadable text: %v, %v", s.name, d, erra, errb)
			case oka != okb || oka && !sameFormula(xa, xb):
				return fmt.Sprintf("check/filter for %s in %s: %s, then %s", s.name, d, filterText(fa, d),
					filterText(fb, d))
			}
		}
	}
	return ""
}

func filterText(fa FilterAnswer, d policyir.Dialect) string {
	if fa.Result != FilterCondition {
		return fa.Result
	}
	if t, ok := fa.Text[d]; ok {
		return fmt.Sprintf("%s %q", fa.Result, t)
	}
	return fa.Result + " without text"
}

// reverse is the relation that reverses every list of the tree and the
// operands of every AND and OR; on two elements a shuffle may leave the order
// as it was, and reverse never does.
var reverse = genRelation{"reverse", func(t *genTree, _ *rand.Rand) *genTree {
	c := t.clone()
	slices.Reverse(c.sets)
	c.eachSet(func(s *genSet) {
		slices.Reverse(s.nested)
		slices.Reverse(s.policies)
		for _, p := range s.policies {
			slices.Reverse(p.rules)
			for _, r := range p.rules {
				r.cond = r.cond.reversed()
			}
		}
	})
	return c
}}

func (c *genCond) reversed() *genCond {
	if c == nil || c.op == "atom" {
		return c
	}
	return &genCond{op: c.op, l: c.r.reversed(), r: c.l.reversed()}
}

// metamorphicViolations applies every relation to tr and returns, by relation
// name, how the answers changed. ok is false where tr itself does not
// generate.
func metamorphicViolations(t *testing.T, tr *genTree, subjects []mmSubject, seed uint64) (map[string]string, bool) {
	t.Helper()
	base, err := metamorphicAnswers(t, tr, subjects)
	if err != nil {
		return nil, false
	}
	out := map[string]string{}
	for i, rel := range append([]genRelation{reverse}, genRelations...) {
		rnd := rand.New(rand.NewPCG(seed, uint64(i)))
		other := rel.apply(tr, rnd)
		got, err := metamorphicAnswers(t, other, subjects)
		if err != nil {
			out[rel.name] = fmt.Sprintf("the tree generates, the transformed one does not: %v", err)
			continue
		}
		if d := metamorphicDiff(subjects, base, got); d != "" {
			out[rel.name] = d + "\ntransformed:\n" + other.policySets()
		}
	}
	return out, true
}

// simplifiedReadSet is a simplified set of read policies, each with one rule
// for the role x and the condition and predicate given.
func simplifiedReadSet(policies ...*genRule) *genSet {
	s := &genSet{id: "s", target: "resourceType == 'doc'", alg: "DENY_UNLESS_PERMIT", simplified: true}
	for i, r := range policies {
		r.id = fmt.Sprintf("r%d", i)
		r.target, r.effect = genRoleTargets[0], "ALLOW"
		s.policies = append(s.policies, &genPolicy{id: fmt.Sprintf("p%d", i), target: "operation == 'read'",
			alg: "DENY_UNLESS_PERMIT", rules: []*genRule{r}})
	}
	return s
}

func regularOf(s *genSet) *genSet {
	c := (&genTree{sets: []*genSet{s}}).clone().sets[0]
	c.simplified = false
	return c
}

// metamorphicNamedTrees are the trees every relation is applied to on every
// run: the shapes that broke a relation once, beside trees that differ from
// them in one respect and keep every relation.
func metamorphicNamedTrees() map[string]*genTree {
	cond := func(atoms ...string) *genCond {
		c := genAtom(atoms[0])
		for _, a := range atoms[1:] {
			c = &genCond{op: "and", l: c, r: genAtom(a)}
		}
		return c
	}
	pred := &genPredicates[0]
	return map[string]*genTree{
		"an unconditional simplified policy before one over a PIP": {sets: []*genSet{simplifiedReadSet(
			&genRule{}, &genRule{cond: cond("subject.g == 'x'")})}},
		"an unconditional simplified policy before one over a PIP and the resource": {sets: []*genSet{
			simplifiedReadSet(&genRule{}, &genRule{cond: cond("subject.g == 'x'", "resource.d == 'y'")})}},
		"a simplified policy with a predicate before one over a PIP": {sets: []*genSet{simplifiedReadSet(
			&genRule{pred: pred}, &genRule{cond: cond("subject.g == 'x'")})}},
		"a regular set of an unconditional policy before one over a PIP": {sets: []*genSet{regularOf(
			simplifiedReadSet(&genRule{}, &genRule{cond: cond("subject.g == 'x'")}))}},
	}
}

// Every combining algorithm is commutative and idempotent, a policy whose
// target holds for no operation asked about takes part in no answer, and ids
// decide nothing; so no relation of [genRelations] changes what check/resource
// or check/filter answers. The trees are named shapes and generated ones.
// REGOGEN_METAMORPHIC_TREES sets how many trees are generated, and
// REGOGEN_METAMORPHIC_SEED draws them from another seed, where every
// violation in a generated tree is reported, listed or not.
func TestAnAnswerDoesNotDependOnTheOrderIdsOrInertPartsOfTheTree(t *testing.T) {
	seed, trees, explore := uint64(1), 64, false
	if s := os.Getenv("REGOGEN_METAMORPHIC_SEED"); s != "" {
		v, err := strconv.ParseUint(s, 10, 64)
		if err != nil {
			t.Fatalf("REGOGEN_METAMORPHIC_SEED=%q: %v", s, err)
		}
		seed, explore = v, true
	}
	if s := os.Getenv("REGOGEN_METAMORPHIC_TREES"); s != "" {
		v, err := strconv.Atoi(s)
		if err != nil {
			t.Fatalf("REGOGEN_METAMORPHIC_TREES=%q: %v", s, err)
		}
		trees = v
	}
	if testing.Short() && os.Getenv("REGOGEN_METAMORPHIC_TREES") == "" {
		trees = 10
	}

	// The cases: every named tree, then the generated ones; a generated tree
	// that does not generate is skipped, a named one fails the test.
	type tcase struct {
		key   string
		tree  *genTree
		seed  uint64
		named bool
	}
	var cases []tcase
	named := metamorphicNamedTrees()
	for _, name := range slices.Sorted(mapKeys(named)) {
		cases = append(cases, tcase{"named/" + name, named[name], 1, true})
	}
	g := newTreeGen(seed)
	for i := range trees {
		cases = append(cases, tcase{fmt.Sprintf("generated/%d", i), g.tree(), seed + uint64(i), false})
	}

	subjects := metamorphicSubjects(t)
	var mu sync.Mutex
	seen := map[string]string{}
	ran := map[string]bool{}
	generated := 0
	t.Run("trees", func(t *testing.T) {
		const workers = 8
		for w := range workers {
			t.Run(fmt.Sprint(w), func(t *testing.T) {
				t.Parallel()
				for i := w; i < len(cases); i += workers {
					c := cases[i]
					vs, ok := metamorphicViolations(t, c.tree, subjects, c.seed)
					if !ok {
						if c.named {
							t.Errorf("%s does not generate:\n%s", c.key, c.tree.policySets())
						}
						continue
					}
					found := map[string]string{}
					for rel, d := range vs {
						key := c.key + "/" + rel
						switch _, known := metamorphicKnown[key]; {
						case c.named:
							found[key] = fmt.Sprintf("%s\ntree:\n%s", d, c.tree.policySets())
						case known && !explore:
							found[key] = d
						default:
							small, sd := shrinkTree(t, c.tree, subjects, c.seed, rel, d)
							found[key] = fmt.Sprintf("%s\nshrunk tree:\n%s", sd, small.policySets())
						}
					}
					mu.Lock()
					if !c.named {
						generated++
					}
					for _, rel := range append([]genRelation{reverse}, genRelations...) {
						ran[c.key+"/"+rel.name] = true
					}
					maps.Copy(seen, found)
					mu.Unlock()
				}
			})
		}
	})
	t.Logf("seed %d: %d of %d generated trees generate", seed, generated, trees)
	if generated < trees/2 {
		t.Errorf("only %d of %d generated trees generate; the generator draws forms the agent refuses", generated, trees)
	}

	for _, key := range slices.Sorted(mapKeys(seen)) {
		if why, known := metamorphicKnown[key]; known && (!explore || !strings.HasPrefix(key, "generated/")) {
			t.Logf("known violation %s (%s):\n%s", key, why, seen[key])
			continue
		}
		t.Errorf("%s changes an answer: %s", key, seen[key])
	}
	for key := range metamorphicKnown {
		if explore && strings.HasPrefix(key, "generated/") {
			continue // the entry names a tree of the default seed
		}
		if _, ok := seen[key]; !ok && ran[key] {
			t.Errorf("%s holds now: remove its entry from metamorphicKnown", key)
		}
	}
}

// shrinkTree removes parts of tr while the relation named rel still changes
// an answer, in at most 300 edits, and returns the smallest tree it reached
// with the difference rel makes in that tree; d is the difference in tr.
func shrinkTree(t *testing.T, tr *genTree, subjects []mmSubject, seed uint64, rel, d string) (*genTree, string) {
	t.Helper()
	steps := 0
	for changed := true; changed && steps < 300; {
		changed = false
		for _, edit := range treeEdits(tr) {
			if steps++; steps > 300 {
				break
			}
			c := edit(tr.clone())
			if vs, ok := metamorphicViolations(t, c, subjects, seed); ok && vs[rel] != "" {
				tr, d, changed = c, vs[rel], true
				break
			}
		}
	}
	return tr, d
}

// treeEdits lists the one-step simplifications of tr, each a function that
// applies it to a clone of tr.
func treeEdits(tr *genTree) []func(*genTree) *genTree {
	var edits []func(*genTree) *genTree
	// nth returns the n-th set in the order eachSet visits them.
	nth := func(c *genTree, n int) *genSet {
		var out *genSet
		k := 0
		c.eachSet(func(s *genSet) {
			if k == n {
				out = s
			}
			k++
		})
		return out
	}
	if len(tr.sets) > 1 {
		for i := range tr.sets {
			edits = append(edits, func(c *genTree) *genTree {
				c.sets = slices.Delete(c.sets, i, i+1)
				return c
			})
		}
	}
	n := 0
	tr.eachSet(func(s *genSet) {
		si := n
		n++
		for ni := range s.nested {
			edits = append(edits, func(c *genTree) *genTree {
				s := nth(c, si)
				s.nested = slices.Delete(s.nested, ni, ni+1)
				return c
			})
		}
		for pi, p := range s.policies {
			if len(s.policies) > 1 {
				edits = append(edits, func(c *genTree) *genTree {
					s := nth(c, si)
					s.policies = slices.Delete(s.policies, pi, pi+1)
					return c
				})
			}
			for ri, r := range p.rules {
				at := func(c *genTree) *genRule { return nth(c, si).policies[pi].rules[ri] }
				if len(p.rules) > 1 {
					edits = append(edits, func(c *genTree) *genTree {
						q := nth(c, si).policies[pi]
						q.rules = slices.Delete(q.rules, ri, ri+1)
						return c
					})
				}
				if r.pred != nil {
					edits = append(edits, func(c *genTree) *genTree { at(c).pred = nil; return c })
				}
				if r.cond != nil {
					edits = append(edits, func(c *genTree) *genTree { at(c).cond = nil; return c })
					if r.cond.op != "atom" {
						edits = append(edits, func(c *genTree) *genTree { at(c).cond = at(c).cond.l; return c })
						edits = append(edits, func(c *genTree) *genTree { at(c).cond = at(c).cond.r; return c })
					}
				}
			}
		}
	})
	return edits
}
