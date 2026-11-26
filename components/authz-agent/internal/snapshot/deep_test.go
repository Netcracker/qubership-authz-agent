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

package snapshot

import (
	"context"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"

	"authz-agent/internal/costcheck"
)

// deepNesting is how many levels deep a text of [TestATextNestedDeepFailsItsLoadOrRequest]
// nests, 1 Mi (1048576): far past any depth limit a parser may set, and past
// the depth at which an unbounded recursion overflows [costcheck.MaxStack].
const deepNesting = 1 << 20

// knownDeepCrashes lists the texts that still kill the process when nested
// deepNesting levels deep, by the name of the case.
var knownDeepCrashes = map[string]costcheck.Known{}

// deepText is a text of a policy-sets or PIPs document, or of a PIP's
// answer, that a parser reads, with its value nested n levels deep.
type deepText struct {
	// name is the case and where the text stands.
	name string
	// field is the export type and the JSON key of the field that holds the
	// text, such as exportRule.rsqlPredicate, or "" for a text no field of the
	// export holds.
	field string
	// docs returns the PIPs and the policy sets that hold the text nested n
	// levels deep. PIP_URL stands for the address of the PIP server.
	docs func(n int) (pips string, sets string)
	// pipAnswer is the body the PIP server answers with, nested n levels
	// deep where the text is the answer.
	pipAnswer func(n int) string
	// ask sends the request that reads the text and returns its answer.
	ask func(t *testing.T, r *Registry) string
	// want is the answer to the text nested one level deep.
	want string
}

// nested wraps inner in n copies of open and close.
func nested(open, inner, close string, n int) string {
	return strings.Repeat(open, n) + inner + strings.Repeat(close, n)
}

// quote returns s as a JSON string.
func quote(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		panic(err)
	}
	return string(b)
}

// allowSet is a DENY_UNLESS_PERMIT set of tenant t on the resource type doc
// whose one rule allows the operation read where predicate holds. predicate
// is the predicate fields of the rule, such as "rsqlPredicate": "…".
func allowSet(predicate string) string {
	return `{"policySetId": "s", "name": "s", "status": "ACTIVE", "tenantId": "t",
		"target": "resourceType == 'doc'", "combiningAlgorithm": "DENY_UNLESS_PERMIT",
		"policies": [{"policyId": "p", "target": "true", "combiningAlgorithm": "DENY_UNLESS_PERMIT", "tenantId": "t",
			"rules": [{"ruleId": "allow", "target": "operation == 'read'", "effect": "ALLOW", "tenantId": "t", ` +
		predicate + `}]}]}`
}

// targetsSet is a DENY_UNLESS_PERMIT set of tenant t whose one rule allows
// where condition holds, with the targets of the set, the policy, and the
// rule as given.
func targetsSet(setTarget, policyTarget, ruleTarget, condition string) string {
	return `{"policySetId": "s", "name": "s", "status": "ACTIVE", "tenantId": "t",
		"target": ` + quote(setTarget) + `, "combiningAlgorithm": "DENY_UNLESS_PERMIT",
		"policies": [{"policyId": "p", "target": ` + quote(policyTarget) + `, "combiningAlgorithm": "DENY_UNLESS_PERMIT",
			"tenantId": "t", "rules": [{"ruleId": "r", "target": ` + quote(ruleTarget) + `,
				"condition": ` + quote(condition) + `, "effect": "ALLOW", "tenantId": "t"}]}]}`
}

// generalPIPOf is a GENERAL PIP subject.g of tenant t at url whose value is
// the body of the answer.
func generalPIPOf(url string) string {
	return `{"tenantId": "t", "name": "subject.g", "pipType": "GENERAL", "url": ` + quote(url) + `, "httpMethod": "GET"}`
}

// jsonPIPOf is a GENERAL PIP subject.g of tenant t at url whose value is what
// jsonPath selects from the body of the answer.
func jsonPIPOf(url, jsonPath string) string {
	return `{"tenantId": "t", "name": "subject.g", "pipType": "GENERAL", "type": "JSON", "url": ` + quote(url) +
		`, "httpMethod": "GET", "jsonPath": ` + quote(jsonPath) + `}`
}

// filterDoc is the answer to a filter of doc in tenant t for the operation
// read, as the service writes it, or the error.
func filterDoc(_ *testing.T, r *Registry) string {
	op := "read"
	a, err := r.Filter(context.Background(), FilterRequest{Subject: Subject{Tenant: "t"}, ResourceType: "doc", Operation: &op})
	if err != nil {
		return "error: " + err.Error()
	}
	raw, err := json.Marshal(a)
	if err != nil {
		return "error: " + err.Error()
	}
	return string(raw)
}

// decideDoc is the result of a request of the user u1 to read a doc in
// tenant t, or the error.
func decideDoc(t *testing.T, r *Registry) string {
	got, err := r.Decide(context.Background(), readDocAs(t, "u1", "t", "x", 1))
	if err != nil {
		return "error: " + err.Error()
	}
	return fmt.Sprintf("%+v", got)
}

// deepTexts holds a case for each text of the documents that may reach a
// parser, whether the agent parses it or passes it through;
// [TestEveryTextOfTheExportIsNestedDeepOrExempt] checks that every field of
// the export has one.
var deepTexts = []deepText{
	{
		name:  "rule.rsqlPredicate of a DENY rule",
		field: "exportRule.rsqlPredicate",
		docs: func(n int) (string, string) {
			return ``, denySet("s", `"rsqlPredicate": `+quote(nested("(", "secret==1", ")", n)))
		},
		ask:  filterDoc,
		want: `{"calculationResult":"USE_FILTER_CONDITION","filterCondition":null,"mongodbFilterCondition":null,"rsqlFilterCondition":"secret!=1","sqlFilterCondition":null,"customFilterCondition":null}`,
	},
	{
		name:  "rule.rsqlPredicate of an ALLOW rule",
		field: "exportRule.rsqlPredicate",
		docs: func(n int) (string, string) {
			return ``, allowSet(`"rsqlPredicate": ` + quote(nested("(", "secret==1", ")", n)))
		},
		ask:  filterDoc,
		want: `{"calculationResult":"USE_FILTER_CONDITION","filterCondition":null,"mongodbFilterCondition":null,"rsqlFilterCondition":"(secret==1)","sqlFilterCondition":null,"customFilterCondition":null}`,
	},
	{
		name:  "rule.mongodbPredicate of a DENY rule",
		field: "exportRule.mongodbPredicate",
		docs: func(n int) (string, string) {
			return ``, denySet("s", `"mongodbPredicate": `+quote(nested(`{"$and": [`, `{"secret": 1}`, `]}`, n)))
		},
		ask:  filterDoc,
		want: `{"calculationResult":"USE_FILTER_CONDITION","filterCondition":null,"mongodbFilterCondition":"{{\"$or\": [{ \"$nor\": [ {\"secret\": 1} ] }]}}","rsqlFilterCondition":null,"sqlFilterCondition":null,"customFilterCondition":null}`,
	},
	{
		name:  "rule.sqlPredicate of a DENY rule",
		field: "exportRule.sqlPredicate",
		docs: func(n int) (string, string) {
			return ``, denySet("s", `"sqlPredicate": `+quote(nested("(", "secret = 1", ")", n)))
		},
		ask:  filterDoc,
		want: `{"calculationResult":"USE_FILTER_CONDITION","filterCondition":null,"mongodbFilterCondition":null,"rsqlFilterCondition":null,"sqlFilterCondition":"NOT ((secret = 1))","customFilterCondition":null}`,
	},
	{
		name:  "rule.predicate of a DENY rule",
		field: "exportRule.predicate",
		docs: func(n int) (string, string) {
			return ``, denySet("s", `"predicate": `+quote(nested("(", "secret.eq(1)", ")", n)))
		},
		ask:  filterDoc,
		want: `{"calculationResult":"USE_FILTER_CONDITION","filterCondition":"((secret.eq(1))).not()","mongodbFilterCondition":null,"rsqlFilterCondition":null,"sqlFilterCondition":null,"customFilterCondition":null}`,
	},
	{
		name:  "a value of the policy-sets document under a key the export ignores",
		field: "",
		docs: func(n int) (string, string) {
			return ``, denySet("s", `"sqlPredicate": "secret = 1", "x-ignored": `+nested("[", "1", "]", n))
		},
		ask:  filterDoc,
		want: `{"calculationResult":"USE_FILTER_CONDITION","filterCondition":null,"mongodbFilterCondition":null,"rsqlFilterCondition":null,"sqlFilterCondition":"NOT (secret = 1)","customFilterCondition":null}`,
	},
	{
		name:  "rule.condition, a jsonpath filter in a filter",
		field: "exportRule.condition",
		docs: func(n int) (string, string) {
			return ``, targetsSet("resourceType == 'doc'", "true", "operation == 'read'",
				"resource.a[?("+nested("@.a[?(", "@.b == 1", ")]", n)+")].b == 1")
		},
		ask:  decideDoc,
		want: "[{Allowed:false Reason:no policy of the tenant allows the operation on the resource}]",
	},
	{
		name:  "rule.condition, a MATCH pattern",
		field: "exportRule.condition",
		docs: func(n int) (string, string) {
			return ``, targetsSet("resourceType == 'doc'", "true", "operation == 'read'",
				"resource.a MATCH "+nested("(", "x", ")", n))
		},
		ask:  decideDoc,
		want: "[{Allowed:true Reason:}]",
	},
	{
		name:  "rule.condition, a regular expression in a jsonpath filter",
		field: "exportRule.condition",
		docs: func(n int) (string, string) {
			return ``, targetsSet("resourceType == 'doc'", "true", "operation == 'read'",
				"resource.a[?(@.s =~ /"+nested("(", "x", ")", n)+"/)].s == 'x'")
		},
		ask:  decideDoc,
		want: "[{Allowed:false Reason:no policy of the tenant allows the operation on the resource}]",
	},
	{
		name:  "pip.jsonPath, a filter in a filter",
		field: "exportPIP.jsonPath",
		docs: func(n int) (string, string) {
			return jsonPIPOf("PIP_URL", "$.a[?("+nested("@.t[?(", "@.p == 1", ")]", n)+")].s"),
				targetsSet("resourceType == 'doc'", "true", "operation == 'read'", "subject.g == 'x'")
		},
		pipAnswer: func(int) string { return `{"a": [{"t": [{"p": 1}], "s": "x"}]}` },
		ask:       decideDoc,
		want:      "[{Allowed:false Reason:no policy of the tenant allows the operation on the resource}]",
	},
	{
		name:  "pip.jsonPath, a regular expression in a filter",
		field: "exportPIP.jsonPath",
		docs: func(n int) (string, string) {
			return jsonPIPOf("PIP_URL", "$.a[?(@.s =~ /"+nested("(", "x", ")", n)+"/)].s"),
				targetsSet("resourceType == 'doc'", "true", "operation == 'read'", "subject.g == 'x'")
		},
		pipAnswer: func(int) string { return `{"a": [{"s": "x"}]}` },
		ask:       decideDoc,
		want:      "[{Allowed:false Reason:no policy of the tenant allows the operation on the resource}]",
	},
	{
		name:  "a value of the PIPs document under a key the export ignores",
		field: "",
		docs: func(n int) (string, string) {
			return strings.TrimSuffix(generalPIPOf("PIP_URL"), "}") + `, "x-ignored": ` + nested("[", "1", "]", n) + "}",
				targetsSet("resourceType == 'doc'", "true", "operation == 'read'", "subject.g == 'x'")
		},
		pipAnswer: func(int) string { return `["x"]` },
		ask:       decideDoc,
		want:      "[{Allowed:true Reason:}]",
	},
	{
		name:  "the answer of a GENERAL PIP",
		field: "",
		docs: func(int) (string, string) {
			return generalPIPOf("PIP_URL"),
				targetsSet("resourceType == 'doc'", "true", "operation == 'read'", "subject.g == 'x'")
		},
		pipAnswer: func(n int) string { return nested("[", `"x"`, "]", n) },
		ask:       decideDoc,
		want:      "[{Allowed:true Reason:}]",
	},
}

// loadAndAsk loads the documents of c with the text nested n levels deep and
// sends the request of c, with a PIP server where c has one. It returns the
// answer, or the error of the load, or the refusal of tenant t.
func loadAndAsk(t *testing.T, c deepText, n int) string {
	pips, sets := c.docs(n)
	if c.pipAnswer != nil {
		answer := c.pipAnswer(n)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(answer))
		}))
		defer srv.Close()
		pips = strings.ReplaceAll(pips, "PIP_URL", srv.URL)
	}
	r := pipRegistry(t)
	policySets, pipsDoc := documents(pips, sets)
	sum, err := r.Load(context.Background(), policySets, pipsDoc)
	if err != nil {
		return "load error: " + err.Error()
	}
	if len(sum.Refused) > 0 {
		return fmt.Sprintf("refused: %+v", sum.Refused)
	}
	return c.ask(t, r)
}

// A text of a policy or PIP document, or of a PIP's answer, nested 1 Mi
// levels deep fails its load or its request, or is answered, and the process
// survives. The same text nested one level deep is answered, so that a parser
// that refuses every text still fails its case.
func TestATextNestedDeepFailsItsLoadOrRequest(t *testing.T) {
	for _, c := range deepTexts {
		t.Run(c.name, func(t *testing.T) {
			if got := loadAndAsk(t, c, 1); got != c.want {
				t.Fatalf("the text nested one level deep: answer = %s, want %s", got, c.want)
			}
			costcheck.Deep(t, knownDeepCrashes[c.name], func() { loadAndAsk(t, c, deepNesting) })
		})
	}
}

// textsWithoutNesting lists the fields of the export that hold no text a
// parser reads nested, each with the reason.
var textsWithoutNesting = map[string]string{
	"exportSet.target":                 "a condition, read by the parser the exportRule.condition cases cover",
	"exportPolicy.target":              "a condition, read by the parser the exportRule.condition cases cover",
	"exportRule.target":                "a condition, read by the parser the exportRule.condition cases cover",
	"exportIterate.foreach":            "compared as a whole with subject.permissionScope",
	"exportCustom.params":              "a JSON value of the document, which the document decoder bounds",
	"exportCustom.predicate":           "the name of a custom predicate, compared as a whole",
	"exportPIP.url":                    "a URL whose ${...} placeholders do not nest",
	"exportSet.iterate":                "an object of the document, which the document decoder bounds",
	"exportSet.policies":               "an array of the document, which the document decoder bounds",
	"exportSet.policySets":             "an array of the document, which the document decoder bounds",
	"exportPolicy.rules":               "an array of the document, which the document decoder bounds",
	"exportRule.customPredicate":       "an object of the document, which the document decoder bounds",
	"exportPIP.defaultValue":           "a JSON value of the document, which the document decoder bounds",
	"exportPIP.headers":                "a JSON value of the document, which the document decoder bounds",
	"exportPIP.requestAttributes":      "a JSON value of the document, which the document decoder bounds",
	"exportPIP.productMapping":         "a JSON value of the document, which the document decoder bounds",
	"exportPIP.customMapping":          "a JSON value of the document, which the document decoder bounds",
	"exportPIP.cacheable":              "a JSON value of the document, which the document decoder bounds",
	"exportPIP.cachePeriod":            "a JSON value of the document, which the document decoder bounds",
	"exportPIP.query":                  "a JSON value of the document, which the document decoder bounds",
	"exportPIP.body":                   "a JSON value of the document, which the document decoder bounds",
	"exportPIP.timeoutSeconds":         "a JSON value of the document, which the document decoder bounds",
	"exportPIP.response":               "a JSON value of the document, which the document decoder bounds",
	"exportSet.tenantId":               "an identifier, compared as a whole",
	"exportSet.policySetId":            "an identifier, compared as a whole",
	"exportSet.name":                   "a name, compared as a whole",
	"exportSet.type":                   "a keyword",
	"exportSet.domain":                 "a name, compared as a whole",
	"exportSet.component":              "a name, compared as a whole",
	"exportSet.status":                 "a keyword",
	"exportSet.combiningAlgorithm":     "a keyword",
	"exportSet.externalId":             "an identifier, compared as a whole",
	"exportIterate.combiningAlgorithm": "a keyword",
	"exportPolicy.tenantId":            "an identifier, compared as a whole",
	"exportPolicy.policyId":            "an identifier, compared as a whole",
	"exportPolicy.name":                "a name, compared as a whole",
	"exportPolicy.combiningAlgorithm":  "a keyword",
	"exportRule.tenantId":              "an identifier, compared as a whole",
	"exportRule.ruleId":                "an identifier, compared as a whole",
	"exportRule.name":                  "a name, compared as a whole",
	"exportRule.ruleType":              "a keyword",
	"exportRule.effect":                "a keyword",
	"exportPIP.tenantId":               "an identifier, compared as a whole",
	"exportPIP.name":                   "a name, compared as a whole",
	"exportPIP.pipType":                "a keyword",
	"exportPIP.type":                   "a keyword",
	"exportPIP.domain":                 "a name, compared as a whole",
	"exportPIP.httpMethod":             "a keyword",
	"exportPIP.header":                 "the name of a request header, compared as a whole",
	"exportPIP.claim":                  "the name of a token claim, compared as a whole",
	"exportPIP.beanName":               "a name, compared as a whole",
	"exportPIP.resourceType":           "a name, compared as a whole",
}

// exportFields returns type.jsonKey for each field of the package-level
// struct types of the policyir export whose names start with export: the
// fields the policy-sets and PIPs documents are read into.
func exportFields(t *testing.T) []string {
	t.Helper()
	const path = "../../../../internal/policyir/export.go"
	f, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	var fields []string
	for _, decl := range f.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok {
			continue
		}
		for _, spec := range gen.Specs {
			ts, ok := spec.(*ast.TypeSpec)
			if !ok || !strings.HasPrefix(ts.Name.Name, "export") {
				continue
			}
			st, ok := ts.Type.(*ast.StructType)
			if !ok {
				continue
			}
			for _, field := range st.Fields.List {
				if field.Tag == nil {
					continue
				}
				tag, err := strconv.Unquote(field.Tag.Value)
				if err != nil {
					t.Fatalf("tag %s of %s: %v", field.Tag.Value, ts.Name.Name, err)
				}
				key, _, _ := strings.Cut(reflect.StructTag(tag).Get("json"), ",")
				if key != "" && key != "-" {
					fields = append(fields, ts.Name.Name+"."+key)
				}
			}
		}
	}
	return fields
}

// Every field the policy-sets and PIPs documents are read into has a case in
// deepTexts or an entry in textsWithoutNesting. A new field fails this test
// until it gets one of the two.
func TestEveryTextOfTheExportIsNestedDeepOrExempt(t *testing.T) {
	fields := exportFields(t)
	if !slices.Contains(fields, "exportRule.rsqlPredicate") {
		t.Fatalf("fields of the export = %v, want them to hold exportRule.rsqlPredicate", fields)
	}
	cased := map[string]bool{}
	for _, c := range deepTexts {
		cased[c.field] = true
	}
	for _, f := range fields {
		if !cased[f] && textsWithoutNesting[f] == "" {
			t.Errorf("field %s of the export has no case in deepTexts and no entry in textsWithoutNesting", f)
		}
		if cased[f] && textsWithoutNesting[f] != "" {
			t.Errorf("field %s of the export has a case in deepTexts and an entry in textsWithoutNesting; delete the entry", f)
		}
	}
	for f := range textsWithoutNesting {
		if !slices.Contains(fields, f) {
			t.Errorf("textsWithoutNesting holds %s, which is no field of the export; delete the entry", f)
		}
	}
}
