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

package jsonpath

import (
	"testing"

	"authz-agent/internal/jsonvalue"
)

func TestALeadingBracketKeySelectsTheMemberOnlyUnderCompileRootKey(t *testing.T) {
	doc, err := jsonvalue.Decode([]byte(`{"a b": {"c": "x"}}`))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		compile func(string) (*Path, error)
		want    Result
	}{
		{"CompileRootKey", CompileRootKey, Result{Kind: KindOne, Value: "x"}},
		{"Compile", Compile, Result{Kind: KindBracket}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := tc.compile(`['a b'].c`)
			if err != nil {
				t.Fatalf("%s(['a b'].c): %v", tc.name, err)
			}
			if got := p.Select(doc); got != tc.want {
				t.Errorf("%s(['a b'].c).Select = %+v, want %+v", tc.name, got, tc.want)
			}
		})
	}
}
