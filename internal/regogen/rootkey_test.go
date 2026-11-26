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
	"encoding/json"
	"math/rand/v2"
	"reflect"
	"testing"
	"time"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"

	"authz-agent/internal/jsonvalue"
	"authz-agent/internal/policyir"
	"authz-agent/internal/regogen/spectables"
)

// rootKeys returns the keys a test writes as $['k']: the ones a dotted
// step cannot spell, and n random ones. A key holds neither ' nor ], which
// end a bracket step.
func rootKeys(t *testing.T, n int) []string {
	t.Helper()
	keys := []string{"a b", "a/b", "a.b", "a..b", "", "https://idp/roles", "a:b", "a-b", "é", "*", "0", "$", "a[0", "a"}
	seed := time.Now().UnixNano()
	t.Logf("random keys from seed %d", seed)
	r := rand.New(rand.NewPCG(uint64(seed), 0))
	alphabet := []rune(" ./:-_*$@?[0aé")
	for range n {
		k := make([]rune, r.IntN(6))
		for i := range k {
			k[i] = alphabet[r.IntN(len(alphabet))]
		}
		keys = append(keys, string(k))
	}
	return keys
}

// rootKeyDocument is a document whose member k is "selected", beside the
// members a misreading of $['k'] as a dotted path or a deep scan selects.
func rootKeyDocument(t *testing.T, k string) string {
	t.Helper()
	key, err := json.Marshal(k)
	if err != nil {
		t.Fatal(err)
	}
	return `{"a": {"b": "nested", "0": "nested"}, "b": "nested", ` + string(key) + `: "selected"}`
}

// A TOKEN PIP's claim $['k'] selects the member k, as $.['k'] does, whatever
// k holds.
func TestATokenClaimWithARootBracketSelectsTheKeyItNames(t *testing.T) {
	want := Resolved{State: spectables.StateValue, Value: "selected"}
	for _, k := range rootKeys(t, 30) {
		t.Run(k, func(t *testing.T) {
			claims := mustDecode(t, rootKeyDocument(t, k)).(*jsonvalue.Object)
			dotted := tokenPIP(&policyir.PIP{Claim: "$.['" + k + "']"}, claims)
			if !reflect.DeepEqual(dotted, want) {
				t.Fatalf("claim $.['%s'] = %+v, want %+v", k, dotted, want)
			}
			if got := tokenPIP(&policyir.PIP{Claim: "$['" + k + "']"}, claims); !reflect.DeepEqual(got, want) {
				t.Errorf("claim $['%s'] = %+v, want %+v, as $.['%s'] gives", k, got, want, k)
			}
		})
	}
}

// A GENERAL PIP's jsonPath $['k'] is accepted and selects the member k of the
// response body, as .['k'] does, whatever k holds.
func TestAPIPJSONPathWithARootBracketSelectsTheKeyItNames(t *testing.T) {
	bctx := rego.BuiltinContext{Context: context.Background()}
	want := Resolved{State: spectables.StateValue, Value: "selected"}
	for _, k := range rootKeys(t, 30) {
		t.Run(k, func(t *testing.T) {
			resp := ast.ObjectTerm(
				[2]*ast.Term{ast.StringTerm("status_code"), ast.IntNumberTerm(200)},
				[2]*ast.Term{ast.StringTerm("raw_body"), ast.StringTerm(rootKeyDocument(t, k))})
			dotted, err := pipResolve(bctx, resp, ".['"+k+"']")
			if err != nil || !reflect.DeepEqual(dotted, want) {
				t.Fatalf("path .['%s'] = %+v, %v, want %+v", k, dotted, err, want)
			}
			jp, err := pipPath(&policyir.PIP{Name: "subject.g", ReturnType: "JSON", JSONPath: "$['" + k + "']"})
			if err != nil {
				t.Fatalf("pipPath($['%s']): %v", k, err)
			}
			if got, err := pipResolve(bctx, resp, jp); err != nil || !reflect.DeepEqual(got, want) {
				t.Errorf("jsonPath $['%s'] read as %q = %+v, %v, want %+v, as .['%s'] gives", k, jp, got, err, want, k)
			}
		})
	}
}

// The replay of a GENERAL PIP whose jsonPath is $['k'] answers with a body
// that the PIP reads back as the value the recording gave, whatever k holds.
func TestAReplayedPIPWithARootBracketJSONPathReadsBackItsValue(t *testing.T) {
	bctx := rego.BuiltinContext{Context: context.Background()}
	want := Resolved{State: spectables.StateValue, Value: "selected"}
	for _, k := range rootKeys(t, 30) {
		t.Run(k, func(t *testing.T) {
			jp, err := pipPath(&policyir.PIP{Name: "subject.g", ReturnType: "JSON", JSONPath: "$['" + k + "']"})
			if err != nil {
				t.Fatalf("pipPath($['%s']): %v", k, err)
			}
			status, body, err := pipAnswer(want, jp)
			if err != nil {
				t.Fatalf("pipAnswer for jsonPath $['%s'] read as %q: %v", k, jp, err)
			}
			resp := ast.ObjectTerm(
				[2]*ast.Term{ast.StringTerm("status_code"), ast.IntNumberTerm(status)},
				[2]*ast.Term{ast.StringTerm("raw_body"), ast.StringTerm(body)})
			if got, err := pipResolve(bctx, resp, jp); err != nil || !reflect.DeepEqual(got, want) {
				t.Errorf("jsonPath $['%s'] reads the replayed body %s as %+v, %v, want %+v", k, body, got, err, want)
			}
		})
	}
}
