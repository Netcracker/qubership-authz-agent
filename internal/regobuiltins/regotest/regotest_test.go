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

package regotest

import (
	"context"
	"testing"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/tester"
)

// module calls each built-in function once in a passing test, and once in a
// test that must fail, so that a runner which does not evaluate the functions
// cannot pass every test.
const module = `package nc_test

test_value if nc.value("A").k == "a"

test_decimal_compare if nc.decimal.compare(0.30000000000000001, 0.3) == 1

test_jsonpath if nc.jsonpath({"a": [1, 2]}, ".a[1]").rec.n == 2

test_value_fails if nc.value("A").k == "A"

test_decimal_compare_fails if nc.decimal.compare(0.30000000000000001, 0.3) == 0

test_jsonpath_fails if nc.jsonpath({"a": [1, 2]}, ".a[1]").rec.n == 1
`

func TestNewRunner_RunsRegoTestsThatCallTheBuiltins(t *testing.T) {
	mod, err := ast.ParseModule("nc_test.rego", module)
	if err != nil {
		t.Fatal(err)
	}
	ch, err := NewRunner().SetModules(map[string]*ast.Module{"nc_test.rego": mod}).RunTests(context.Background(), nil)
	if err != nil {
		t.Fatalf("RunTests: %v", err)
	}
	got := map[string]string{}
	for r := range ch {
		got[r.Name] = outcome(r)
	}
	want := map[string]string{
		"test_value":                 "pass",
		"test_decimal_compare":       "pass",
		"test_jsonpath":              "pass",
		"test_value_fails":           "fail",
		"test_decimal_compare_fails": "fail",
		"test_jsonpath_fails":        "fail",
	}
	for name, w := range want {
		if got[name] != w {
			t.Errorf("%s: %q, want %q", name, got[name], w)
		}
	}
}

func outcome(r *tester.Result) string {
	switch {
	case r.Error != nil:
		return "error: " + r.Error.Error()
	case r.Fail:
		return "fail"
	}
	return "pass"
}
