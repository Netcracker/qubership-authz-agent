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

// module holds a test that passes and a test that fails, so that a runner
// which reports every test as passed cannot pass.
const module = `package nc_test

test_passes if lower("A") == "a"

test_fails if lower("A") == "A"
`

func TestNewRunner_RunsRegoTests(t *testing.T) {
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
		"test_passes": "pass",
		"test_fails":  "fail",
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

// print() in a test writes to the output the runner captures, as it does under
// a runner without the built-in functions.
func TestNewRunner_CapturesPrintOutput(t *testing.T) {
	mod, err := ast.ParseModule("print_test.rego", `package nc_test

test_print if {
	print("lower", lower("A"))
}
`)
	if err != nil {
		t.Fatal(err)
	}
	ch, err := NewRunner().CapturePrintOutput(true).SetModules(map[string]*ast.Module{"print_test.rego": mod}).RunTests(context.Background(), nil)
	if err != nil {
		t.Fatalf("RunTests: %v", err)
	}
	for r := range ch {
		if got := string(r.Output); outcome(r) != "pass" || got != "lower a\n" {
			t.Errorf("%s: %s with output %q, want pass with output \"lower a\\n\"", r.Name, outcome(r), got)
		}
	}
}
