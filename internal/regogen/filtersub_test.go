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
	"go/ast"
	"go/parser"
	gotoken "go/token"
	"io"
	"net/http"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/open-policy-agent/opa/v1/rego"

	"authz-agent/internal/jsonvalue"
	"authz-agent/internal/policyir"
	"authz-agent/internal/regobuiltins"
	"authz-agent/internal/regogen/spectables"
)

// placeholderKnown lists the rows of TestAPlaceholderDeniesExactlyWhenItsSourceIsUnread
// that answer otherwise today, by source, state, and effect. A listed row is
// logged; a listed row that answers as the rule asks fails the test until its
// entry is removed, and an unlisted one fails it.
var placeholderKnown = map[string]string{
	"roles/ERROR/ALLOW": f10,
	"roles/ERROR/DENY":  f10,
}

const f10 = "F10: ${subject.roles} renders a roles claim in ERROR as an empty list, so the filter writes " +
	"c=in=() or c=out=() instead of denying"

// placeholderStateRule is what the answer of a filter whose predicate names
// a source must be when the source is in a state: DENY where the agent could
// not read the source, a text where it read one, and a state outside either
// is not asked about. ABSENT is a value of a subject attribute (no roles),
// the lack of a source (no MAPPING PIP), and, for a GENERAL or FILTERED PIP,
// an anonymous request the PIP is not called for, whose text keeps the
// placeholder as written; no answer is decided for it, so none is required.
// The other states without a rule belong to the resource.
var placeholderStateRule = map[spectables.State]string{
	spectables.StateError:        FilterDeny,
	spectables.StateValue:        FilterCondition,
	spectables.StateNull:         FilterCondition,
	spectables.StateEmptyColl:    FilterCondition,
	spectables.StatePIPEmpty:     FilterCondition,
	spectables.StatePIPNull:      FilterCondition,
	spectables.StateSingleOdd:    FilterCondition,
	spectables.StateScalarOdd:    FilterCondition,
	spectables.StateAbsent:       "",
	spectables.StateScopeOutside: "",
	spectables.StateEmptySel:     "",
	spectables.StateIndexOOB:     "",
}

// placeholderSourcesWithoutDomain lists the sources a placeholder may name
// whose kind has no domain in the table, with the reason they need no row.
var placeholderSourcesWithoutDomain = map[string]string{
	"pip:PERMISSION_SCOPE": "a predicate reads a permission scope through ${subject.permissionScope.<key>}, " +
		"the row of subj.permissionScope",
}

// placeholderSources returns the sources [substituter.source] reads a
// placeholder ${subject.<name>} from, as the kinds of the table name them:
// subj.<name> for each name its switch lists or prefix it cuts, and
// pip:<type> for each [policyir.PIPType].
func placeholderSources(t *testing.T) []string {
	t.Helper()
	fset := gotoken.NewFileSet()
	f, err := parser.ParseFile(fset, "filtersub.go", nil, 0)
	if err != nil {
		t.Fatalf("ParseFile(filtersub.go): %v", err)
	}
	var out []string
	ast.Inspect(f, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "source" || fn.Recv == nil {
			return true
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.SwitchStmt:
				if id, ok := x.Tag.(*ast.Ident); ok && id.Name == "name" {
					for _, c := range x.Body.List {
						for _, e := range c.(*ast.CaseClause).List {
							out = append(out, "subj."+unquote(t, e))
						}
					}
				}
			case *ast.CallExpr:
				if sel, ok := x.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "CutPrefix" && len(x.Args) == 2 {
					if id, ok := x.Args[0].(*ast.Ident); ok && id.Name == "name" {
						out = append(out, "subj."+strings.TrimSuffix(unquote(t, x.Args[1]), "."))
					}
				}
			}
			return true
		})
		return false
	})
	files, err := filepath.Glob("../policyir/*.go")
	if err != nil {
		t.Fatalf("Glob(../policyir/*.go): %v", err)
	}
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("ParseFile(%s): %v", name, err)
		}
		for _, d := range f.Decls {
			g, ok := d.(*ast.GenDecl)
			if !ok || g.Tok != gotoken.CONST {
				continue
			}
			for _, s := range g.Specs {
				vs := s.(*ast.ValueSpec)
				if id, ok := vs.Type.(*ast.Ident); ok && id.Name == "PIPType" {
					for _, v := range vs.Values {
						out = append(out, "pip:"+unquote(t, v))
					}
				}
			}
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

func unquote(t *testing.T, e ast.Expr) string {
	t.Helper()
	lit, ok := e.(*ast.BasicLit)
	if !ok || lit.Kind != gotoken.STRING {
		t.Fatalf("want a string literal, got %T", e)
	}
	s, err := strconv.Unquote(lit.Value)
	if err != nil {
		t.Fatalf("Unquote(%s): %v", lit.Value, err)
	}
	return s
}

// placeholderSetup is a request in which a source is in one state: the PIP
// declarations the tenant needs, the placeholder that names the source, the
// request, and the response every PIP call gets (nil where the PIP values
// of the request answer them).
type placeholderSetup struct {
	pips, name string
	iterate    bool
	req        Request
	answer     *Resolved
}

// placeholderProducer puts a source in a state: through its producer where
// the producer is cheap to drive, and by setting the state directly
// otherwise. ok is false for a state the test has no way to produce.
type placeholderProducer func(t *testing.T, state spectables.State) (s placeholderSetup, ok bool)

// subjectAttribute sets the value of subject.<name> in the request directly:
// value in state VALUE and no value in any other.
func subjectAttribute(name, value string) placeholderProducer {
	return func(t *testing.T, state spectables.State) (placeholderSetup, bool) {
		v := Resolved{State: state}
		if state == spectables.StateValue {
			v = resolved(t, "VALUE", value)
		}
		return placeholderSetup{name: "subject." + name, req: Request{Values: map[string]Resolved{
			specKey("subj", name): v}}}, true
	}
}

func generalPIP(pipType string) placeholderProducer {
	return func(t *testing.T, state spectables.State) (placeholderSetup, bool) {
		v := Resolved{State: state}
		switch state {
		case spectables.StateValue:
			v = resolved(t, "VALUE", `["x", "q"]`)
		case spectables.StateSingleOdd:
			v = resolved(t, "SINGLE_ODD", `[1]`)
		case spectables.StateScalarOdd:
			v = resolved(t, "SCALAR_ODD", `1`)
		}
		return placeholderSetup{name: "subject.g", answer: &v,
			pips: `{"name": "subject.g", "pipType": "` + pipType + `", "url": "http://g", "requestAttributes": {}}`}, true
	}
}

var placeholderProducers = map[string]placeholderProducer{
	"subj.id":     subjectAttribute("id", `"x"`),
	"subj.name":   subjectAttribute("name", `"x"`),
	"subj.type":   subjectAttribute("type", `"USER"`),
	"subj.roles":  subjectAttribute("roles", `["x", "q"]`),
	"subj.scopes": subjectAttribute("scopes", `["x", "q"]`),
	"subj.permissions": func(t *testing.T, state spectables.State) (placeholderSetup, bool) {
		claims := map[spectables.State]string{spectables.StateValue: roles(`["admin"]`),
			spectables.StateEmptyColl: roles(`["other"]`), spectables.StateError: roles(`"admin"`)}[state]
		if claims == "" {
			return placeholderSetup{}, false
		}
		pips := mapping(`{"subject.roles": {"admin": ["x", "q"]}}`, `null`)
		if got := permissionsOf(t, pips, claims, nil).State; got != state {
			t.Fatalf("subject.permissions for claims %s is %s, want %s", claims, got, state)
		}
		req := Request{Claims: mustDecode(t, claims).(*jsonvalue.Object)}
		SubjectOf(req.Claims, false, DefaultSubjectRules).Apply(&req)
		return placeholderSetup{name: "subject.permissions", req: req, pips: pips}, true
	},
	"subj.permissionScope": func(t *testing.T, state spectables.State) (placeholderSetup, bool) {
		grant := map[spectables.State][]jsonvalue.Value{spectables.StateValue: {"x", "q"},
			spectables.StateEmptyColl: {}}
		vals, ok := grant[state]
		if !ok {
			return placeholderSetup{}, false
		}
		return placeholderSetup{name: "subject.permissionScope.k", iterate: true, req: Request{Scope: &Scope{
			Passes: []map[string]Resolved{{}}, grants: []map[string][]jsonvalue.Value{{"k": vals}}}}}, true
	},
	"pip:TOKEN": func(t *testing.T, state spectables.State) (placeholderSetup, bool) {
		// a claim outside the jsonPath subset reads as ERROR
		in, ok := map[spectables.State]struct{ claim, claims string }{
			spectables.StateValue:    {"dept", `{"dept": "x"}`},
			spectables.StatePIPEmpty: {"dept", `{}`},
			spectables.StateError:    {"dept[", `{"dept": "x"}`},
		}[state]
		if !ok {
			return placeholderSetup{}, false
		}
		claims := mustDecode(t, in.claims).(*jsonvalue.Object)
		if got := tokenPIP(&policyir.PIP{Claim: in.claim}, claims).State; got != state {
			t.Fatalf("the TOKEN PIP of claim %q over %s is %s, want %s", in.claim, in.claims, got, state)
		}
		return placeholderSetup{name: "subject.t", req: Request{Claims: claims},
			pips: `{"name": "subject.t", "pipType": "TOKEN", "claim": ` + strconv.Quote(in.claim) + `}`}, true
	},
	"pip:HEADER": func(t *testing.T, state spectables.State) (placeholderSetup, bool) {
		headers, ok := map[spectables.State]map[string]string{spectables.StateValue: {"x-t": "x"},
			spectables.StatePIPEmpty: {}}[state]
		if !ok {
			return placeholderSetup{}, false
		}
		if got := headerPIP(&policyir.PIP{Header: "X-T"}, headers).State; got != state {
			t.Fatalf("the HEADER PIP over %v is %s, want %s", headers, got, state)
		}
		return placeholderSetup{name: "subject.h", req: Request{Headers: headers},
			pips: `{"name": "subject.h", "pipType": "HEADER", "header": "X-T"}`}, true
	},
	"pip:GENERAL":  generalPIP("GENERAL"),
	"pip:FILTERED": generalPIP("FILTERED"),
}

// placeholderTree is a tenant with one set of the algorithm that lets an
// unconditional rule of effect decide, the rule's predicate naming
// ${<name>} in every dialect, and the PIPs pips; with iterate, the set
// iterates over the permission scope.
func placeholderTree(t *testing.T, effect, name, pips string, iterate bool) (*policyir.Tree, error) {
	t.Helper()
	alg := map[string]string{"ALLOW": "DENY_UNLESS_PERMIT", "DENY": "PERMIT_UNLESS_DENY"}[effect]
	it := ""
	if iterate {
		it = fmt.Sprintf(`"iterate": {"foreach": "subject.permissionScope", "combiningAlgorithm": %q},`, alg)
	}
	p := "${" + name + "}"
	rule := map[string]string{"ruleId": "r1", "target": "true", "effect": effect, "tenantId": "t1",
		"rsqlPredicate": "c=in=(" + p + ")", "sqlPredicate": "c IN (" + p + ")",
		"mongodbPredicate": `{"c": {"$in": ` + p + `}}`, "predicate": "c.in(" + p + ")"}
	sets := fmt.Sprintf(`{"policySets": [{"policySetId": "s1", "name": "s1", "status": "ACTIVE",
		"target": "resourceType == 'doc'", "combiningAlgorithm": %[1]q, "tenantId": "t1", %[2]s
		"policies": [{"policyId": "p1", "target": "true", "combiningAlgorithm": %[1]q, "tenantId": "t1",
			"rules": [%[3]s]}]}]}`, alg, it, jsonText(stringObject(rule)))
	if pips != "" {
		pips = strings.ReplaceAll(pips, `{"name"`, `{"tenantId": "t1", "name"`)
	}
	exp, err := policyir.FromRegular([]byte(sets), []byte(`{"pips": [`+pips+`]}`))
	if err != nil {
		return nil, err
	}
	tree, ok := exp.Trees["t1"]
	if !ok {
		return nil, fmt.Errorf("no tree of t1; failed %v, dropped %v", exp.Failed, exp.Dropped)
	}
	return tree, nil
}

func stringObject(m map[string]string) *jsonvalue.Object {
	o := jsonvalue.NewObject()
	for _, k := range slices.Sorted(func(yield func(string) bool) {
		for k := range m {
			if !yield(k) {
				return
			}
		}
	}) {
		o.Set(k, m[k])
	}
	return o
}

// fixedAnswer answers every request with the response a PIP reads back as
// one value.
type fixedAnswer struct {
	status int
	body   string
}

func (a fixedAnswer) RoundTrip(r *http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: a.status, Body: io.NopCloser(strings.NewReader(a.body)),
		Header: http.Header{}, Request: r}, nil
}

// placeholderAnswer answers check/filter for the request of s.
func placeholderAnswer(t *testing.T, m *Module, s placeholderSetup) FilterAnswer {
	t.Helper()
	req := s.req
	req.Body = Body{Operation: "read", ResourceType: "doc"}
	if req.Values == nil {
		req.Values = map[string]Resolved{}
	}
	if s.answer == nil {
		return evalFilter(t, m, prepareFilter(t, m), req)
	}
	status, body, err := pipAnswer(*s.answer, "")
	if err != nil {
		t.Fatalf("pipAnswer(%v): %v", *s.answer, err)
	}
	in, err := Project(m, req)
	if err != nil {
		t.Fatalf("Project: %v", err)
	}
	h := &regobuiltins.HTTP{Client: &http.Client{Transport: fixedAnswer{status, body}},
		Token: func() (string, error) { return "own", nil }}
	ctx := regobuiltins.WithCalls(h.Context(context.Background()))
	rs, err := prepareFilter(t, m).Eval(in.Context(ctx), rego.EvalParsedInput(in.Value()))
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

// For every source a placeholder of a filter predicate can name, every state
// the table lets the source's producer give, and both effects, an
// unconditional rule whose predicate holds the placeholder answers DENY
// where the source could not be read, and a text where it could. The
// sources come from the code and the states from the domain of the source's
// kind, so a new state, or a new source the switch of [substituter.source]
// lists, is a new row; a row the test cannot
// produce fails it until placeholderProducers can.
func TestAPlaceholderDeniesExactlyWhenItsSourceIsUnread(t *testing.T) {
	for _, s := range spectables.States {
		if _, ok := placeholderStateRule[s]; !ok {
			t.Errorf("state %s has no entry in placeholderStateRule", s)
		}
	}
	tab := table(t)
	rows := map[string]bool{}
	for _, src := range placeholderSources(t) {
		dom, ok := tab.Domain(spectables.Kind(src))
		if !ok {
			if _, listed := placeholderSourcesWithoutDomain[src]; !listed {
				t.Errorf("the placeholder source %s has no domain in the table", src)
			}
			continue
		}
		for _, state := range dom.States {
			want := placeholderStateRule[state]
			if want == "" {
				continue
			}
			produce, ok := placeholderProducers[src]
			var setup placeholderSetup
			if ok {
				setup, ok = produce(t, state)
			}
			if !ok {
				t.Errorf("no way to put the placeholder source %s in state %s; add one to placeholderProducers",
					src, state)
				continue
			}
			for _, effect := range []string{"ALLOW", "DENY"} {
				short := strings.TrimPrefix(strings.TrimPrefix(src, "subj."), "pip:")
				key := fmt.Sprintf("%s/%s/%s", short, state, effect)
				rows[key] = true
				t.Run(key, func(t *testing.T) {
					tree, err := placeholderTree(t, effect, setup.name, setup.pips, setup.iterate)
					if err != nil {
						t.Fatalf("the tenant does not load: %v", err)
					}
					m, err := GenerateFilter(tree, tab, DefaultOptions())
					if err != nil {
						t.Fatalf("GenerateFilter: %v", err)
					}
					fa := placeholderAnswer(t, m, setup)
					if fa.Result == want {
						if why, listed := placeholderKnown[key]; listed {
							t.Errorf("${%s} in %s under %s answers %s as it should; remove its entry %q (%s) "+
								"from placeholderKnown", setup.name, state, effect, fa.Result, key, why)
						}
						return
					}
					if why, listed := placeholderKnown[key]; listed {
						t.Logf("known: %s answers %s %v (%s)", key, fa.Result, fa.Text, why)
						return
					}
					t.Errorf("${%s} in %s under an unconditional %s rule: %s %v, want %s",
						setup.name, state, effect, fa.Result, fa.Text, want)
				})
			}
		}
	}
	for key := range placeholderKnown {
		if !rows[key] {
			t.Errorf("the table has no row %s any longer; remove its entry from placeholderKnown", key)
		}
	}
}
