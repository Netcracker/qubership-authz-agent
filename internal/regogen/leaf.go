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
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"

	"authz-agent/internal/policyir"
	"authz-agent/internal/regogen/spectables"
)

var errUndeclared = errors.New("the PIP is not declared")

// leafRails are the two rails of a leaf: the clauses where it is true and the
// clauses where it is false. A request on neither rail leaves the leaf
// undefined; threeValued is set when such a request exists.
type leafRails struct {
	t, f        dnf
	threeValued bool
	// subjectOnly is set when every expression reads only the subject's
	// projected attributes, so that the leaf can join a subject group.
	subjectOnly bool
	// failed holds where the leaf is unknown because a source it reads
	// failed on the request: a point of a side at the failure of its source
	// whose outcome depends on the source's value, or a PIP that is not
	// declared. It is false for a leaf that reads no such source.
	failed dnf
	// row is set on a leaf over the resource in check/filter, which is true
	// on the rows it matches.
	row *rowAtom
}

type point struct {
	st spectables.State
	cl spectables.Class
}

func (p point) spec(k spectables.Kind) spectables.Point {
	return spectables.Point{Kind: k, State: p.st, Class: p.cl}
}

// points lists the (state, class) pairs the side can be in at this leaf.
func (s *side) points() []point {
	switch {
	case s.lit != nil:
		return []point{{spectables.StateValue, s.lit.class}}
	case s.isPattern():
		return []point{{spectables.StateValue, spectables.ClassString}}
	case s.fixed != "":
		return []point{{s.fixed, ""}}
	}
	var out []point
	for _, st := range s.ref.domain.States {
		if st != spectables.StateValue {
			out = append(out, point{st, ""})
			continue
		}
		for _, cl := range s.ref.domain.Classes {
			out = append(out, point{st, cl})
		}
	}
	return out
}

// field is the expression that reads one field of the side's value record.
func (s *side) field(f string) string {
	s.ref.read |= fieldBit(f)
	if s.ref.Network {
		return "p_" + s.ref.Var + "." + f
	}
	if s.ref.Pass {
		return "p." + f + refIndex(s.ref.ID)
	}
	return "input." + f + refIndex(s.ref.ID)
}

// bind is the clause that binds the record of a network PIP or of a lazily
// read resource path, empty for any other side.
func (s *side) bind() clause {
	if s.ref == nil || !s.ref.Network {
		return nil
	}
	if s.ref.Path != "" {
		return clause{{cls: clsBuiltin, text: fmt.Sprintf("p_%s := nc.resource_path(input.%s, %s)", s.ref.Var, memberResource,
			lit(s.ref.Path))}}
	}
	if s.ref.pip != nil {
		return clause{{cls: clsBuiltin, text: fmt.Sprintf("p_%s := pip_%s", s.ref.Var, s.ref.Var)}}
	}
	if s.ref.ent != nil {
		return clause{{cls: clsBuiltin, text: fmt.Sprintf("p_%s := ent_%s", s.ref.Var, s.ref.Var)}}
	}
	return clause{{cls: clsBuiltin, text: fmt.Sprintf("p_%s := nc.pip(%s)", s.ref.Var, lit(s.ref.ID))}}
}

// cls is the class of a check of the side: after the binding for a network PIP.
func (s *side) cls(c int) int {
	if s.ref != nil && s.ref.Network {
		return clsAfterBuilt
	}
	return c
}

// at is the clause that holds exactly when the side is at the point; empty
// when the side has no other point.
func (s *side) at(p point) clause {
	if s.ref == nil || len(s.points()) == 1 {
		return nil
	}
	if p.st != spectables.StateValue {
		return conj(s.bind(), clause{{cls: s.cls(clsCheck), text: fmt.Sprintf("%s == %q", s.field(fieldState), p.st),
			fact: fact{ref: s.ref.ID, field: factState, val: string(p.st)},
			test: refTest(s, &test{kind: "state", val: string(p.st)})}})
	}
	return conj(s.bind(), clause{{cls: s.cls(clsCheck), text: fmt.Sprintf("%s == %q", s.field(fieldClass), p.cl),
		fact: fact{ref: s.ref.ID, field: factClass, val: string(p.cl)}, test: refTest(s, &test{kind: "cls", val: string(p.cl)})}})
}

// compare builds the rails of a comparison from the specification's cells.
// Every point of the operands' domains gets the outcome of its cell: a constant
// becomes a clause of the operands' states, and a cell whose outcome depends on
// the values becomes the template of the operator. The ERROR point of a source
// that failed gets the outcome [failedCells] gives it instead. A cell that is
// unsupported, a bad request, or value-dependent without a template is a
// generation error.
func (g *gen) compare(c policyir.Compare, ctx spectables.Context) (leafRails, error) {
	leafText := func() string {
		leaf := policyir.FormatOperand(c.Left) + " " + opText(spectables.Operator(c.Op))
		if c.Right != nil {
			leaf += " " + policyir.FormatOperand(c.Right)
		}
		return leaf
	}
	if g.filter && (readsResource(c.Left) || readsResource(c.Right)) {
		// check/filter has no resource: what a comparison over it gives
		// row by row is the predicate's part of the answer
		g.reportLeaf(leafText(), nil)
		rails := leafRails{threeValued: true, row: rowAtomOf(c)}
		other := c.Left
		if readsResource(c.Left) {
			other = c.Right
		}
		if other == nil || readsResource(other) {
			return rails, nil
		}
		// a source the resource is compared with leaves the leaf unknown on
		// every row where it fails
		S, err := g.side(other)
		switch {
		case errors.Is(err, errUndeclared):
			rails.failed = dnfTrue
		case err != nil:
			return leafRails{}, err
		}
		if S != nil {
			for _, p := range S.points() {
				if S.failed(p) {
					rails.failed = union(rails.failed, dnf{S.at(p)})
				}
			}
		}
		return rails, nil
	}
	L, err := g.side(c.Left)
	if err != nil {
		if errors.Is(err, errUndeclared) {
			g.reportLeaf(leafText(), nil)
			return leafRails{threeValued: true, failed: dnfTrue}, nil
		}
		return leafRails{}, err
	}
	var R *side
	if c.Right != nil {
		if R, err = g.side(c.Right); err != nil {
			if errors.Is(err, errUndeclared) {
				g.reportLeaf(leafText(), nil)
				return leafRails{threeValued: true, failed: dnfTrue}, nil
			}
			return leafRails{}, err
		}
	}
	op := spectables.Operator(c.Op)
	lps := L.points()
	rps := []point{{}}
	if R != nil {
		rps = R.points()
	}
	cells := make([][]spectables.Cell, len(lps))
	for i, lp := range lps {
		cells[i] = make([]spectables.Cell, len(rps))
		for j, rp := range rps {
			key := spectables.Key{Op: op, Left: lp.spec(L.kind), Context: ctx}
			if R != nil {
				key.Right = rp.spec(R.kind)
			}
			cell, err := g.tab.Lookup(key)
			if err != nil {
				return leafRails{}, err
			}
			switch cell.Outcome {
			case spectables.OutcomeUnsupported, spectables.OutcomeBadRequest:
				return leafRails{}, gap(FormSpecification, fmt.Errorf("%s(%s %v, %s %v) at %s: the specification answers %s",
					op, L.kind, lp, kindOf(R), rps[j], ctx.Place, cell.Outcome))
			}
			cells[i][j] = cell
		}
	}
	g.stats.Lookups += len(lps) * len(rps)
	failedL, failedR := failedCells(cells, L, lps, R, rps)

	var rails leafRails
	// unknownAll reports whether the leaf is unknown at the point i of the
	// left side whatever the right side holds
	unknownAll := func(i int) bool {
		return !slices.ContainsFunc(cells[i], func(c spectables.Cell) bool { return c.Outcome != spectables.OutcomeU })
	}
	for i := range lps {
		if failedL[i] && unknownAll(i) {
			rails.failed = union(rails.failed, dnf{L.at(lps[i])})
			continue
		}
		for j := range rps {
			if (failedL[i] || failedR[j]) && cells[i][j].Outcome == spectables.OutcomeU {
				rails.failed = union(rails.failed, dnf{conj(L.at(lps[i]), rightAt(R, rps[j]))})
			}
		}
	}
	// add puts c on the rail of outcome o
	add := func(o spectables.Outcome, c clause) {
		switch o {
		case spectables.OutcomeT:
			rails.t = union(rails.t, dnf{c})
		case spectables.OutcomeF:
			rails.f = union(rails.f, dnf{c})
		case spectables.OutcomeU:
			rails.threeValued = true
		}
	}
	constant := func(cs []spectables.Cell) (spectables.Outcome, bool) {
		o := cs[0].Outcome
		for _, c := range cs {
			if c.Outcome != o || o == spectables.OutcomeByValue {
				return "", false
			}
		}
		return o, true
	}
	var templates map[[2]int]string
	if g.opt.Report {
		templates = map[[2]int]string{}
	}
	coveredL := make([]bool, len(lps))
	coveredR := make([]bool, len(rps))
	for j := range rps {
		col := make([]spectables.Cell, len(lps))
		for i := range lps {
			col[i] = cells[i][j]
		}
		if o, ok := constant(col); ok && R != nil && R.ref != nil {
			coveredR[j] = true
			add(o, R.at(rps[j]))
		}
	}
	for i := range lps {
		if o, ok := constant(cells[i]); ok {
			coveredL[i] = true
			add(o, L.at(lps[i]))
		}
	}
	for i, lp := range lps {
		if coveredL[i] {
			continue
		}
		for j, rp := range rps {
			if coveredR[j] {
				continue
			}
			cell := cells[i][j]
			if cell.Outcome != spectables.OutcomeByValue {
				add(cell.Outcome, conj(L.at(lp), rightAt(R, rp)))
				continue
			}
			tmpl, err := g.byValue(&rails, op, L, R, cells, lps, rps, i, j)
			if err != nil {
				return leafRails{}, err
			}
			if templates != nil {
				templates[[2]int{i, j}] = tmpl
			}
		}
	}
	for _, s := range []*side{L, R} {
		rails.t, rails.f = joinClasses(rails.t, s), joinClasses(rails.f, s)
	}
	if g.opt.Report {
		g.reportLeaf(leafText(), reportCells(L, R, lps, rps, cells, templates))
	}
	rails.subjectOnly = sideSubjectOnly(L) && (R == nil || sideSubjectOnly(R))
	return rails, nil
}

// failedCells replaces the cell of each point where a side's source failed
// ([side.failed]): the source has no value, so the point gets the outcome
// every value of the source gives against the other side's point, and U
// where the values give different outcomes or depend on the value. A rule
// over a failed source is then unknown wherever its outcome depends on the
// source, whatever outcome the table gives the failure itself. A
// point where both sides failed is U. failedCells returns, for each point of
// each side, whether the side's source failed there.
func failedCells(cells [][]spectables.Cell, L *side, lps []point, R *side, rps []point) (failedL, failedR []bool) {
	failedL = make([]bool, len(lps))
	for i, p := range lps {
		failedL[i] = L.failed(p)
	}
	failedR = make([]bool, len(rps))
	for j, p := range rps {
		failedR[j] = R != nil && R.failed(p)
	}
	unknown := spectables.Cell{Outcome: spectables.OutcomeU}
	// valueOutcome is the one constant outcome of the cells at, or U
	valueOutcome := func(at [][2]int) spectables.Cell {
		var o spectables.Outcome
		for _, ij := range at {
			c := cells[ij[0]][ij[1]]
			if c.Outcome != spectables.OutcomeT && c.Outcome != spectables.OutcomeF || o != "" && c.Outcome != o {
				return unknown
			}
			o = c.Outcome
		}
		if o == "" {
			return unknown
		}
		return spectables.Cell{Outcome: o}
	}
	out := make([][]spectables.Cell, len(cells))
	for i := range cells {
		out[i] = slices.Clone(cells[i])
		for j := range cells[i] {
			var at [][2]int
			switch {
			case failedL[i] && failedR[j]:
				out[i][j] = unknown
				continue
			case failedL[i]:
				for k := range lps {
					if !failedL[k] {
						at = append(at, [2]int{k, j})
					}
				}
			case failedR[j]:
				for k := range rps {
					if !failedR[k] {
						at = append(at, [2]int{i, k})
					}
				}
			default:
				continue
			}
			if cells[i][j].Outcome != spectables.OutcomeU {
				out[i][j] = valueOutcome(at)
			}
		}
	}
	for i := range cells {
		copy(cells[i], out[i])
	}
	return failedL, failedR
}

// failed reports whether the side at p is a source that failed: the ERROR
// state of a GENERAL or FILTERED PIP and of subject.entitledResources, whose
// call failed, and of a resource path without a dot at its end, whose
// selection stopped as too large.
func (s *side) failed(p point) bool {
	if s.ref == nil || p.st != spectables.StateError {
		return false
	}
	switch s.ref.Kind {
	case spectables.KindPIPGeneral, spectables.KindPIPFiltered, spectables.KindEntitled:
		return true
	case spectables.KindResPath, spectables.KindResNested, spectables.KindResJSONPath:
		return s.ref.dotState == ""
	}
	return false
}

// joinClasses replaces each set of clauses of d that are equal except for the
// class they require of s with one clause that requires any of those classes,
// so d holds for the same requests with fewer clauses. A template that reads
// a field several classes share, such as element_keys, gives such a set: CONTAINS ANY
// with literals writes a membership per literal for each class.
func joinClasses(d dnf, s *side) dnf {
	if s == nil || s.ref == nil || len(d) < 2 {
		return d
	}
	type joined struct {
		at      int
		classes []string
	}
	out := make(dnf, 0, len(d))
	var groups []*joined
	byRest := map[string]int{}
	for _, c := range d {
		at := slices.IndexFunc(c, func(e expr) bool { return e.fact.field == factClass && e.fact.ref == s.ref.ID })
		if at < 0 || c[at].fact.vals != nil {
			out, groups = append(out, c), append(groups, nil)
			continue
		}
		rest := slices.Delete(slices.Clone(c), at, at+1).key()
		if k, ok := byRest[rest]; ok {
			groups[k].classes = append(groups[k].classes, c[at].fact.val)
			continue
		}
		byRest[rest] = len(out)
		out, groups = append(out, c), append(groups, &joined{at: at, classes: []string{c[at].fact.val}})
	}
	for k, j := range groups {
		if j == nil || len(j.classes) < 2 {
			continue
		}
		slices.Sort(j.classes)
		c := slices.Clone(out[k])
		c[j.at] = expr{cls: c[j.at].cls, text: s.field(fieldClass) + " in " + setLit(j.classes),
			fact: fact{ref: s.ref.ID, field: factClass, vals: j.classes}, test: refTest(s, &test{kind: "clsin", set: j.classes})}
		out[k] = c
	}
	return out
}

func rightAt(R *side, p point) clause {
	if R == nil {
		return nil
	}
	return R.at(p)
}

// byValue adds the template rows of the value-dependent cell (i, j) and
// returns how it answered the cell, as [CellReport.Template] names it. A true
// row leaves out the class check of a side when the template applies, with the
// same true row, to every class whose record has the fields the row reads:
// then the fields themselves select the classes, and the index sees the bare
// equality. A false row keeps the checks, because its negations also hold
// where the fields are missing.
func (g *gen) byValue(rails *leafRails, op spectables.Operator, L, R *side, cells [][]spectables.Cell,
	lps, rps []point, i, j int) (string, error) {
	lp, rp := lps[i], rps[j]
	cell := cells[i][j]
	// A one-element GENERAL list of null, a boolean, or an object
	// (SINGLE_ODD) is a list that may hold a null element to the collection
	// operators: the templates of class list_with_null, whose guard reads the
	// record's has_null.
	odd := func(p point) point {
		if p.st == spectables.StateSingleOdd {
			return point{spectables.StateValue, spectables.ClassNullElement}
		}
		return p
	}
	oddL, oddR := lp.st == spectables.StateSingleOdd, rp.st == spectables.StateSingleOdd
	lp, rp = odd(lp), odd(rp)
	if oddL != oddR && (lp.st != spectables.StateValue || R != nil && rp.st != spectables.StateValue) {
		// the other side has no value, so only a null element of the odd
		// list decides: it fails the PIP (undefined), and any other element
		// gives the cell's one remaining outcome
		oddSide := L
		if oddR {
			oddSide = R
		}
		var rest []spectables.Outcome
		for _, o := range cell.Outcomes {
			if o != spectables.OutcomeU {
				rest = append(rest, o)
			}
		}
		if len(rest) != 1 || !slices.Contains(cell.Outcomes, spectables.OutcomeU) {
			g.stats.NoTemplate[fmt.Sprintf("%s(%s %s, %s %s) odd", op, L.kind, lps[i].st, kindOf(R), rps[j].st)]++
			return "", gap(FormGenerator, fmt.Errorf("%s: value-dependent cell in state %s × %s has no template", op, lps[i].st, rps[j].st))
		}
		// the other side reads as an empty list, so a collection rule
		// compares the odd list with nothing, or with a resource list no
		// element equals, and gives that one outcome
		if r, ok := uncovered(cell.ValueRule, spectables.RuleSingleOdd, spectables.RuleNullElementEnds,
			spectables.RuleContainsAny, spectables.RuleInAny, spectables.RuleContainsRightAttributeList); ok {
			g.stats.NoTemplate[fmt.Sprintf("%s(%s %s, %s %s) rule %s", op, L.kind, lps[i].st, kindOf(R), rps[j].st, r)]++
			return "", gap(FormGenerator, fmt.Errorf("%s: value rule %s of a SINGLE_ODD cell has no template", op, r))
		}
		// the guard reads the odd list in its own state, so it states no
		// fact of state VALUE, which would contradict that state
		g2 := conj(oddSide.bind(), clause{{cls: oddSide.cls(clsCheck), text: "not " + oddSide.field(fieldHasNull),
			test: refTest(oddSide, &test{kind: "non0"})}})
		c := conj(L.at(lps[i]), rightAt(R, rps[j]), g2)
		if rest[0] == spectables.OutcomeT {
			rails.t = union(rails.t, dnf{c})
		} else {
			rails.f = union(rails.f, dnf{c})
		}
		rails.threeValued = true
		return "single_odd against no value", nil
	}
	if (op == spectables.OpEQ || op == spectables.OpNE) && lp.st == spectables.StateValue &&
		lp.cl == spectables.ClassString && L.ref != nil && R != nil && rp.st != spectables.StateValue &&
		len(cell.ValueRule) == 1 && cell.ValueRule[0] == spectables.RuleEq {
		// a right operand in a special state whose cell evaluates the values
		// is read as an empty list, and a string equals it by the text []
		eq := conj(L.bind(), clause{{cls: L.cls(clsCheck), text: L.field(fieldKey) + ` == "[]"`, fact: vfact(L)}})
		ne := conj(L.bind(), clause{{cls: L.cls(clsCheck), text: L.field(fieldKey) + ` != "[]"`, fact: vfact(L)}})
		if op == spectables.OpNE {
			eq, ne = ne, eq
		}
		at := conj(L.at(lps[i]), rightAt(R, rps[j]))
		rails.t = union(rails.t, prod(dnf{at}, dnf{eq}, true))
		rails.f = union(rails.f, prod(dnf{at}, dnf{ne}, true))
		return "eq with the right side read as []", nil
	}
	if (op == spectables.OpEQ || op == spectables.OpNE) && lp.st == spectables.StateValue &&
		lp.cl == spectables.ClassString && L.ref == nil && L.lit != nil && R != nil && R.ref != nil &&
		rp.st != spectables.StateValue && len(cell.ValueRule) == 1 && cell.ValueRule[0] == spectables.RuleEq {
		// the same reading with a string literal on the left, whose text is
		// known at generation
		at := conj(L.at(lps[i]), rightAt(R, rps[j]))
		if (L.lit.text == "[]") == (op == spectables.OpEQ) {
			rails.t = union(rails.t, dnf{at})
		} else {
			rails.f = union(rails.f, dnf{at})
		}
		return "eq of a literal with the right side read as []", nil
	}
	if lp.st != spectables.StateValue || R != nil && rp.st != spectables.StateValue {
		g.stats.NoTemplate[fmt.Sprintf("%s(%s %s, %s %s)", op, L.kind, lp.st, kindOf(R), rp.st)]++
		return "", gap(FormGenerator, fmt.Errorf("%s(%s %s, %s %s): value-dependent cell in a state other than VALUE has no template", op,
			L.kind, lp.st, kindOf(R), rp.st))
	}
	if L.ref == nil && L.lit != nil && R != nil && R.ref == nil {
		// both values known at generation: a copy of the tree for one
		// operation compares the operation with a literal
		v, ok := constCompare(op, L, R)
		if _, bad := uncovered(cell.ValueRule, spectables.RuleEq, spectables.RuleInAny, spectables.RuleMatch,
			spectables.RuleRel, spectables.RuleSubset); bad {
			ok = false
		}
		if !ok {
			g.stats.NoTemplate[fmt.Sprintf("%s(%s, %s) of two literals", op, L.kind, R.kind)]++
			return "", gap(FormGenerator, fmt.Errorf("%s(%s, %s): no constant template", op, L.kind, R.kind))
		}
		if v {
			rails.t = union(rails.t, dnfTrue)
		} else {
			rails.f = union(rails.f, dnfTrue)
		}
		return "two literals compared at generation", nil
	}
	tp, ok := template(op, L, R, lp.cl, rp.cl)
	if ok && rightListOp[op] && R != nil && R.ref != nil && !isRes(R.kind) && !oddR &&
		(rp.cl == spectables.ClassList || rp.cl == spectables.ClassNullElement || rp.cl == spectables.ClassNested) &&
		!slices.Contains(cell.ValueRule, spectables.RuleRightListScalarOps) {
		// the templates compare such a list element by element, which holds
		// only for a list of at most one value; a cell that names no
		// right_list_scalar_ops has not seen a longer one
		g.stats.NoTemplate[fmt.Sprintf("%s(%s %s, %s %s) without rule %s", op, L.kind, lp.cl, kindOf(R), rp.cl,
			spectables.RuleRightListScalarOps)]++
		return "", gap(FormGenerator, fmt.Errorf("%s(%s %s, %s %s): a list on the right without rule %s has no template", op, L.kind,
			lp.cl, kindOf(R), rp.cl, spectables.RuleRightListScalarOps))
	}
	if ok && slices.Contains(cell.ValueRule, spectables.RuleRightListScalarOps) {
		if err := g.rightListScalarOps(&tp, R, rp); err != nil {
			g.stats.NoTemplate[fmt.Sprintf("%s(%s %s, %s %s) rule %s", op, L.kind, lp.cl, kindOf(R), rp.cl,
				spectables.RuleRightListScalarOps)]++
			return "", fmt.Errorf("%s(%s %s, %s %s): %w", op, L.kind, lp.cl, kindOf(R), rp.cl, err)
		}
	}
	if ok && (op == spectables.OpContainsAny || op == spectables.OpNotContainsAny) && (oddL || oddR) &&
		lp.cl == spectables.ClassNullElement && rp.cl == spectables.ClassNullElement {
		// A SINGLE_ODD list of null fails the PIP on the left of CONTAINS
		// ANY. On the right it is a value, and a list of a boolean or an
		// object holds no null, so a null element on the left ends the rule
		// there as it does against any list without one. NOT CONTAINS ANY
		// ends where CONTAINS ANY does, and the guard applies to both rails.
		g := dnf{conj(L.bind(), clause{{cls: L.cls(clsCheck), text: "not " + L.field(fieldHasNull), fact: vfact(L)}})}
		if oddR && !oddL {
			g = append(g, conj(R.bind(), clause{{cls: R.cls(clsCheck), text: R.field(fieldHasNull), fact: vfact(R)}}))
		}
		tp.t, tp.f = prod(g, tp.t, true), prod(g, tp.f, true)
		tp.undefined = true
		tp.rules[spectables.RuleNullElementEnds] = true
	}
	if ok && slices.Contains(cell.Outcomes, spectables.OutcomeU) && !tp.undefined {
		g.stats.NoTemplate[fmt.Sprintf("%s(%s %s, %s %s) with U", op, L.kind, lp.cl, kindOf(R), rp.cl)]++
		return "", gap(FormGenerator, fmt.Errorf("%s: value-dependent cell with an undefined outcome has no template", op))
	}
	if ok && tp.undefined && !slices.Contains(cell.Outcomes, spectables.OutcomeU) {
		g.stats.NoTemplate[fmt.Sprintf("%s(%s %s, %s %s) without U", op, L.kind, lp.cl, kindOf(R), rp.cl)]++
		return "", gap(FormGenerator, fmt.Errorf("%s: the template leaves a value undefined where the cell has no undefined outcome", op))
	}
	if tp.undefined {
		rails.threeValued = true
	}
	if oddL || oddR {
		// the template's expressions read the odd list in its own state, not
		// in VALUE
		tp.t, tp.f = withoutValueFacts(tp.t, L, oddL, R, oddR), withoutValueFacts(tp.f, L, oddL, R, oddR)
	}
	if !ok {
		g.stats.NoTemplate[fmt.Sprintf("%s(%s %s, %s %s)", op, L.kind, lp.cl, kindOf(R), rp.cl)]++
		return "", gap(FormGenerator, fmt.Errorf("%s(%s %s, %s %s): no template for a value-dependent cell", op, L.kind, lp.cl,
			kindOf(R), rp.cl))
	}
	have := slices.Collect(maps.Keys(tp.rules))
	if oddL || oddR {
		have = append(have, spectables.RuleSingleOdd)
	}
	if r, bad := uncovered(cell.ValueRule, have...); bad {
		g.stats.NoTemplate[fmt.Sprintf("%s(%s %s, %s %s) rule %s", op, L.kind, lp.cl, kindOf(R), rp.cl, r)]++
		return "", gap(FormGenerator, fmt.Errorf("%s(%s %s, %s %s): value rule %s has no template", op, L.kind, lp.cl, kindOf(R), rp.cl, r))
	}
	// same reports whether the template's true rows are the same at every
	// point of s whose record carries the fields they read, with the other
	// side at its point. A SINGLE_ODD record carries element_keys too, so a
	// row that reads element_keys keeps its check where the domain has that state.
	same := func(s *side, isLeft bool) bool {
		if s == nil || s.ref == nil {
			return true
		}
		fields := tp.fields[s]
		if len(fields) == 0 || fields["guard"] ||
			fields[fieldElementKeys] && slices.Contains(s.ref.domain.States, spectables.StateSingleOdd) {
			return false
		}
		classes := tp.fieldClasses(s)
		if len(classes) == 0 {
			return false
		}
		want := tp.t.key()
		for _, cl := range classes {
			var c spectables.Cell
			lc, rc := lp.cl, rp.cl
			if isLeft {
				idx := slices.Index(lps, point{spectables.StateValue, cl})
				if idx < 0 {
					return false
				}
				c, lc = cells[idx][j], cl
			} else {
				idx := slices.Index(rps, point{spectables.StateValue, cl})
				if idx < 0 {
					return false
				}
				c, rc = cells[i][idx], cl
			}
			if c.Outcome != spectables.OutcomeByValue {
				return false
			}
			other, ok := template(op, L, R, lc, rc)
			if !ok || other.t.key() != want {
				return false
			}
		}
		return true
	}
	// At most one side drops its check: with both dropped, a row would also
	// hold at the pairs where both sides moved, which no check above covers.
	gl, gr := L.at(lps[i]), rightAt(R, rps[j])
	tl, tr := gl, gr
	if !oddL && same(L, true) {
		tl = L.bind()
	} else if R != nil && !oddR && same(R, false) {
		tr = R.bind()
	}
	rails.t = union(rails.t, prod(dnf{conj(tl, tr)}, tp.t, true))
	rails.f = union(rails.f, prod(dnf{conj(gl, gr)}, tp.f, true))
	if !g.opt.Report {
		return "", nil
	}
	if oddL || oddR {
		tp.rules[spectables.RuleSingleOdd] = true
	}
	return ruleNames(tp.rules), nil
}

func kindOf(s *side) spectables.Kind {
	if s == nil {
		return "-"
	}
	return s.kind
}

// sideSubjectOnly reports whether a side reads only what Go projects from the
// subject before Eval: a literal, or a subject attribute that is not a network
// PIP.
func sideSubjectOnly(s *side) bool {
	if s.ref == nil {
		return s.fixed == ""
	}
	if s.ref.Network {
		return false
	}
	switch s.ref.Kind {
	case spectables.KindSubjID, spectables.KindSubjName, spectables.KindSubjType, spectables.KindSubjRoles,
		spectables.KindSubjScopes, spectables.KindSubjPermissions, spectables.KindPIPToken,
		spectables.KindPIPHeader, spectables.KindPIPMapping:
		return true
	}
	return false
}

// constCompare compares two values known at generation, and returns false as
// its second result for an operator it does not evaluate.
func constCompare(op spectables.Operator, L, R *side) (bool, bool) {
	if pos, ok := negated[op]; ok {
		v, ok := constCompare(pos, L, R)
		return !v, ok
	}
	switch op {
	case spectables.OpEQ:
		if isScalar(L.lit.class) && isScalar(R.lit.class) {
			return L.lit.key == R.lit.key, true
		}
	case spectables.OpIn:
		if isScalar(L.lit.class) {
			return slices.Contains(R.lit.keys, L.lit.key), true
		}
	case spectables.OpIsSubset:
		t := &test{kind: "subset", sets: L.lit.subsetLeft, set: R.lit.subsetRight}
		return t.subsetHolds(nil), true
	case spectables.OpLT, spectables.OpLE, spectables.OpGT, spectables.OpGE:
		if isScalar(L.lit.class) && isScalar(R.lit.class) {
			return relHolds(string(op), L.lit.num, R.lit.num), true
		}
	case spectables.OpMatch:
		if R.isPattern() && L.lit.class == spectables.ClassString {
			rx, err := matchRegex(R.pattern)
			if err != nil {
				return false, false
			}
			return regexp.MustCompile(rx).MatchString(L.lit.text), true
		}
	}
	return false, false
}

// withoutValueFacts drops the requirement of state VALUE that template
// expressions put on an odd side.
func withoutValueFacts(d dnf, L *side, oddL bool, R *side, oddR bool) dnf {
	out := make(dnf, len(d))
	for i, c := range d {
		nc := make(clause, len(c))
		for j, e := range c {
			if e.fact.field == factValue && (oddL && L.ref != nil && e.fact.ref == L.ref.ID ||
				oddR && R != nil && R.ref != nil && e.fact.ref == R.ref.ID) {
				e.fact = fact{}
			}
			nc[j] = e
		}
		out[i] = nc
	}
	return out
}

// uncovered returns the first rule of the cell that have does not list, and
// whether there is one.
func uncovered(rules []spectables.ValueRule, have ...spectables.ValueRule) (spectables.ValueRule, bool) {
	for _, r := range rules {
		if !slices.Contains(have, r) {
			return r, true
		}
	}
	return "", false
}

// rightListScalarOps adds the rule right_list_scalar_ops to the template of a
// cell that names it: a list of two or more values on the right answers with
// the profile's setting right_list_scalar_ops before the values are compared,
// for the negated operators too, and a shorter list compares as the template
// says. A cell of CONTAINS with a list attribute on the right has no base
// template, so it fails generation before this is reached.
func (g *gen) rightListScalarOps(tp *tpl, R *side, rp point) error {
	if R == nil || R.ref == nil || !isListClass(rp.cl) {
		return fmt.Errorf("value rule %s needs a list attribute on the right", spectables.RuleRightListScalarOps)
	}
	knob, err := g.stringKnob("right_list_scalar_ops")
	if err != nil {
		return err
	}
	// the setting holds a legacy outcome; the agent ends no rule and fails
	// no decision there (an end is false, an error unknown)
	outcome, ok := map[string]spectables.Outcome{"T": spectables.OutcomeT, "F": spectables.OutcomeF,
		"ABORT": spectables.OutcomeF, "ERR": spectables.OutcomeU}[knob]
	if !ok {
		return fmt.Errorf("knob right_list_scalar_ops is %q, not an outcome", knob)
	}
	long := conj(R.bind(), clause{{cls: R.cls(clsCheck), text: R.field(fieldLength) + " > 1", fact: vfact(R)}})
	short := conj(R.bind(), clause{{cls: R.cls(clsCheck), text: R.field(fieldLength) + " <= 1", fact: vfact(R)}})
	tp.t = prod(dnf{short}, tp.t, true)
	tp.f = prod(dnf{short}, tp.f, true)
	switch outcome {
	case spectables.OutcomeT:
		tp.t = union(tp.t, dnf{long})
	case spectables.OutcomeF:
		tp.f = union(tp.f, dnf{long})
	default:
		tp.undefined = true
	}
	if tp.fields[R] == nil {
		tp.fields[R] = map[string]bool{}
	}
	tp.fields[R][fieldLength] = true
	tp.rules[spectables.RuleRightListScalarOps] = true
	return nil
}

// rightListOp lists the operators that answer right_list_scalar_ops for a
// list of two or more values of the subject or a PIP on the right.
var rightListOp = map[spectables.Operator]bool{spectables.OpEQ: true, spectables.OpNE: true,
	spectables.OpContains: true, spectables.OpNotContains: true}

// readsResource reports whether operand o reads the resource of the request.
func readsResource(o policyir.Operand) bool {
	_, ok := o.(policyir.Resource)
	return ok
}
