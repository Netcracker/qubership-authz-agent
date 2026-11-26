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
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/open-policy-agent/opa/v1/rego"

	"authz-agent/internal/policyir"
)

// placementKnown lists the conditions that generate in a plain rule and fail
// in another place today, keyed by place and condition. A listed case is
// logged; a listed case that generates fails the test until its entry is
// removed, and an unlisted one fails it.
var placementKnown = map[string]string{}

// placementGaps lists the places where a form is refused by design, keyed as
// [placementKnown]: each is a decision of the generator, not a defect, and is
// held to the same rule, so an entry that generates fails the test.
var placementGaps = map[string]string{
	"iterate | subject allowed 'other' on resource": "a decision for another operation inside an iterate " +
		"needs a copy of the tree per pass, which the generator does not build",
	"iterate | subject denied 'other' on resource": "a decision for another operation inside an iterate " +
		"needs a copy of the tree per pass, which the generator does not build",
}

// The places a condition can stand in. The condition c reads the operation
// write wherever it stands, so a request for write in the plain place and a
// request for read in the copy that subject allowed reads ask the same
// question.
var placements = []struct {
	name string
	sets func(c string) string
}{
	{"plain", func(c string) string {
		return placementSet("resourceType == 'doc'", "true", `{"ruleId": "w", "target": "operation == 'write'", `+
			`"condition": `+genJSON(c)+`, "effect": "ALLOW", "tenantId": "t1"}`, "")
	}},
	{"subject allowed", func(c string) string {
		return placementSet("resourceType == 'doc'", "true", `{"ruleId": "r", "target": "operation == 'read'", `+
			`"condition": "subject allowed 'write' on resource", "effect": "ALLOW", "tenantId": "t1"}, `+
			`{"ruleId": "w", "target": "operation == 'write'", "condition": `+genJSON(c)+
			`, "effect": "ALLOW", "tenantId": "t1"}`, "")
	}},
	{"iterate", func(c string) string {
		return placementSet("resourceType == 'doc'", "true", `{"ruleId": "w", "target": "operation == 'write'", `+
			`"condition": `+genJSON(c)+`, "effect": "ALLOW", "tenantId": "t1"}`,
			`"iterate": {"foreach": "subject.permissionScope", "combiningAlgorithm": "DENY_UNLESS_PERMIT"}, `)
	}},
	{"set target", func(c string) string {
		return placementSet("resourceType == 'doc' AND "+c, "true", `{"ruleId": "w", `+
			`"target": "operation == 'write'", "effect": "ALLOW", "tenantId": "t1"}`, "")
	}},
	{"policy target", func(c string) string {
		return placementSet("resourceType == 'doc'", c, `{"ruleId": "w", "target": "operation == 'write'", `+
			`"effect": "ALLOW", "tenantId": "t1"}`, "")
	}},
}

// placementSet is the export of one set of the target given, one policy of
// the target given, and the rules given, all DENY_UNLESS_PERMIT.
func placementSet(setTarget, policyTarget, rules, iterate string) string {
	return fmt.Sprintf(`{"policySets": [{"policySetId": "s1", "name": "s1", "status": "ACTIVE", "target": %s, `+
		`"combiningAlgorithm": "DENY_UNLESS_PERMIT", "tenantId": "t1", %s"policies": [{"policyId": "p1", `+
		`"target": %s, "combiningAlgorithm": "DENY_UNLESS_PERMIT", "tenantId": "t1", "rules": [%s]}]}]}`,
		genJSON(setTarget), iterate, genJSON(policyTarget), rules)
}

// placementTree loads sets with subject.g declared as a GENERAL PIP; a load
// that fails or leaves no tree returns the reason.
func placementTree(sets string) (*policyir.Tree, error) {
	exp, err := policyir.FromRegular([]byte(sets),
		[]byte(`{"pips": [{"tenantId": "t1", "name": "subject.g", "pipType": "GENERAL", "url": "http://g"}]}`))
	if err != nil {
		return nil, err
	}
	if e, ok := exp.Failed["t1"]; ok {
		return nil, e
	}
	tree, ok := exp.Trees["t1"]
	if !ok {
		return nil, fmt.Errorf("no tree: dropped %v", exp.Dropped)
	}
	return tree, nil
}

// operatorSpelling is the text the parser reads as op.
func operatorSpelling(op policyir.Operator) string {
	switch op {
	case policyir.OpEQ:
		return "=="
	case policyir.OpNE:
		return "!="
	case policyir.OpLT:
		return "<"
	case policyir.OpLE:
		return "<="
	case policyir.OpGT:
		return ">"
	case policyir.OpGE:
		return ">="
	}
	return strings.ReplaceAll(string(op), "_", " ")
}

// placementConditions are every operator between operands of every kind a
// condition reads, then the access atoms. Each comparison is checked to parse
// as the operator it was spelled for, and an operator with no comparison that
// parses fails the test, so an operator added to the language joins with its
// spelling or fails here.
func placementConditions(t *testing.T) []string {
	t.Helper()
	lefts := []string{"operation", "resourceType", "resource.a", "subject.g", "subject.id", "subject.roles",
		"subject.permissionScope", "subject.permissionScope.domain", "'write'", "5"}
	rights := []string{"'write'", "'write', 'x'", "resource.b", "subject.g", "operation", "a/*", "5"}
	var out []string
	for _, op := range policyir.Operators() {
		rs := rights
		if op.Unary() {
			rs = []string{""}
		}
		n := len(out)
		for _, l := range lefts {
			for _, r := range rs {
				c := strings.TrimSpace(l + " " + operatorSpelling(op) + " " + r)
				parsed, err := policyir.ParseCondition(c, policyir.PlaceRuleCondition, "")
				if err != nil {
					continue
				}
				if cmp, ok := parsed.Disjuncts[0][0].(policyir.Compare); !ok || cmp.Op != op {
					t.Fatalf("%q parses as %v, want the operator %s", c, parsed.Disjuncts, op)
				}
				out = append(out, c)
			}
		}
		if len(out) == n {
			t.Fatalf("no comparison by %s parses: spell it in operatorSpelling", op)
		}
	}
	// An access atom names an operation no rule grants: one that names write
	// would read the rule it stands in, and the copy reads that cycle one level
	// deeper than the plain rule, so the depth limit decides it differently.
	return append(out, "subject allowed 'other' on resource", "subject denied 'other' on resource")
}

// placementValues are the values a plain rule and the copy subject allowed
// reads are both asked about: subject.g as a string, a list, failed, and
// null, beside resource values that do and do not equal the literals. A
// number or a boolean in g is not asked.
func placementValues(t *testing.T) map[string]map[string]Resolved {
	t.Helper()
	others := func(g Resolved) map[string]Resolved {
		return map[string]Resolved{
			`["subj","g"]`: g, `["subj","id"]`: resolved(t, "VALUE", `"write"`),
			`["subj","roles"]`: resolved(t, "VALUE", `["write","x"]`),
			`["res",".a"]`:     resolved(t, "VALUE", `"write"`), `["res",".b"]`: resolved(t, "VALUE", `"x"`),
			`["subj","permissionScope"]`:        asPIPList(resolved(t, "VALUE", `["write","x"]`)),
			`["subj","permissionScope.domain"]`: resolved(t, "VALUE", `"write"`),
		}
	}
	return map[string]map[string]Resolved{
		`g="write"`:             others(resolved(t, "VALUE", `"write"`)),
		`g="x"`:                 others(resolved(t, "VALUE", `"x"`)),
		`g=["write","x"]`:       others(asPIPList(resolved(t, "VALUE", `["write","x"]`))),
		`g="5"`:                 others(resolved(t, "VALUE", `"5"`)),
		`g failed`:              others(resolved(t, "ERROR", "")),
		`g null`:                others(resolved(t, "PIP_NULL", "")),
		`g="a/b"`:               others(resolved(t, "VALUE", `"a/b"`)),
		`g=["x","y"], a absent`: placementWith(others(asPIPList(resolved(t, "VALUE", `["x","y"]`))), `["res",".a"]`, resolved(t, "ABSENT", "")),
	}
}

// asPIPList marks a list as the value a PIP answered with several values.
func asPIPList(r Resolved) Resolved {
	r.PIPList = true
	return r
}

func placementWith(m map[string]Resolved, key string, v Resolved) map[string]Resolved {
	m[key] = v
	return m
}

// placementOutcome generates the module of sets; it returns the module and ""
// where it generates, and otherwise why not.
func placementOutcome(t *testing.T, sets string) (*Module, string) {
	t.Helper()
	tree, err := placementTree(sets)
	if err != nil {
		return nil, "load: " + err.Error()
	}
	m, err := Generate(tree, table(t), DefaultOptions())
	if err != nil {
		var re *RejectedError
		if errors.As(err, &re) {
			return nil, "rejected: " + re.Rejections[0].Text
		}
		return nil, "error: " + err.Error()
	}
	return m, ""
}

// A condition that generates in a plain rule generates wherever the tree can
// put it: in the copy of the tree that subject allowed reads, in an iterate,
// in a set target, in a policy target, and in the module of check/filter. In the copy it
// also decides as the plain rule does, since the copy is the same rule read
// for the operation that subject allowed names. A place where the loader,
// policyir.FromRegular, refuses the form counts as a failure of that place.
func TestAConditionThatGeneratesInARuleGeneratesAndDecidesAlikeInEveryPlace(t *testing.T) {
	values := placementValues(t)
	conds := placementConditions(t)
	var (
		mu       sync.Mutex
		failures = map[string]string{}
		notPlain int
	)
	fail := func(key, why string) {
		mu.Lock()
		defer mu.Unlock()
		failures[key] = why
	}
	const workers = 8
	t.Run("conditions", func(t *testing.T) {
		for w := range workers {
			t.Run(fmt.Sprint(w), func(t *testing.T) {
				t.Parallel()
				for i := w; i < len(conds); i += workers {
					n := placementCheck(t, conds[i], values, fail)
					mu.Lock()
					notPlain += n
					mu.Unlock()
				}
			})
		}
	})
	t.Logf("%d conditions: %d generate in no plain rule", len(conds), notPlain)
	for _, key := range slices.Sorted(mapKeys(failures)) {
		if why, ok := placementKnown[key]; ok {
			t.Logf("known violation %s (%s): %s", key, why, failures[key])
			continue
		}
		if why, ok := placementGaps[key]; ok {
			t.Logf("gap by design %s (%s): %s", key, why, failures[key])
			continue
		}
		t.Errorf("%s: %s", key, failures[key])
	}
	for _, list := range []map[string]string{placementKnown, placementGaps} {
		for _, key := range slices.Sorted(mapKeys(list)) {
			if _, ok := failures[key]; !ok {
				t.Errorf("%s generates and decides alike now: remove its entry", key)
			}
		}
	}
}

// placementCheck asks every place about the condition c and reports each
// place where it fails by fail. It returns 1 where c does not generate in a
// plain rule, and 0 otherwise.
func placementCheck(t *testing.T, c string, values map[string]map[string]Resolved,
	fail func(key, why string)) (notPlain int) {
	t.Helper()
	plain, why := placementOutcome(t, placements[0].sets(c))
	if why != "" {
		// A condition that does not generate in a plain rule generates nowhere,
		// so it tells nothing about places: it is counted, not checked.
		return 1
	}
	if tree, err := placementTree(placements[0].sets(c)); err != nil {
		t.Fatalf("load of %q: %v", c, err)
	} else if _, err := GenerateFilter(tree, table(t), DefaultOptions()); err != nil {
		fail("check/filter | "+c, err.Error())
	}
	plainQuery := prepareAllow(t, plain)
	for _, p := range placements[1:] {
		key := p.name + " | " + c
		m, why := placementOutcome(t, p.sets(c))
		switch {
		case why != "":
			fail(key, why)
			continue
		case p.name != "subject allowed":
			continue
		}
		copyQuery := prepareAllow(t, m)
		for _, name := range slices.Sorted(mapKeys(values)) {
			v := values[name]
			want := evalAllow(t, plain, plainQuery, Request{Body: Body{Operation: "write", ResourceType: "doc"}, Values: v})
			got := evalAllow(t, m, copyQuery, Request{Body: Body{Operation: "read", ResourceType: "doc"}, Values: v})
			if got != want {
				fail(key, fmt.Sprintf("allow(read) = %v where %s, but the rule it reads allows write: %v", got, name,
					want))
				break
			}
		}
	}
	return 0
}

// prepareAllow compiles the query of allow; unlike evalModule, it keeps no
// state shared between tests, so parallel tests may call it.
func prepareAllow(t *testing.T, m *Module) rego.PreparedEvalQuery {
	t.Helper()
	pq, err := rego.New(append([]func(*rego.Rego){rego.Query("data." + DefaultOptions().Package + ".allow"),
		rego.Module("gen.rego", m.Text)}, Builtins()...)...).PrepareForEval(context.Background())
	if err != nil {
		t.Fatalf("PrepareForEval: %v\n%s", err, m.Text)
	}
	return pq
}

func evalAllow(t *testing.T, m *Module, pq rego.PreparedEvalQuery, req Request) bool {
	t.Helper()
	in, err := Project(m, req)
	if err != nil {
		t.Fatalf("Project: %v", err)
	}
	rs, err := pq.Eval(in.Context(replayContext(t, in)), rego.EvalParsedInput(in.Value()))
	if err != nil {
		t.Fatalf("Eval: %v", err)
	}
	return len(rs) == 1 && rs[0].Expressions[0].Value == true
}

func mapKeys[V any](m map[string]V) func(yield func(string) bool) {
	return func(yield func(string) bool) {
		for k := range m {
			if !yield(k) {
				return
			}
		}
	}
}
