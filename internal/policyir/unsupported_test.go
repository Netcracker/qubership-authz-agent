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

package policyir

import (
	"slices"
	"testing"
)

func TestTreeUnsupportedIsEmptyForAValidTree(t *testing.T) {
	t.Parallel()

	p := validParts()
	tree, err := NewTree(p.simplified, p.sets, p.pips)
	if err != nil {
		t.Fatal(err)
	}
	if got := tree.Unsupported(); len(got) != 0 {
		t.Errorf("Unsupported() = %v, want none", got)
	}
}

// An iterate counts as nested under any iterating ancestor, not only under its
// parent, so s4 below s3, which does not iterate, is reported too.
func TestTreeUnsupportedListsEveryForm(t *testing.T) {
	t.Parallel()

	p := validParts()
	p.simplified[0].Policies[0].Condition = one(PlaceSimplified,
		Compare{Op: OpEQ, Left: Unsupported{Form: FormJSONPath, Text: "resource.a[:]"}, Right: String{Value: "x"}})
	p.rule().Condition = one(PlaceRuleCondition,
		readOp, Unsupported{Form: FormOperand, Text: "subject.x.y.z"})
	p.sets[0].Policies[0].Target = one(PlacePolicyTarget,
		Compare{Op: OpEQ, Left: Resource{Path: ".a"}, Right: Unsupported{Form: FormPIPType, Text: "subject.scope"}})
	p.sets[0].Sets = append(p.sets[0].Sets,
		&PolicySet{ID: "s3", Sets: []*PolicySet{{ID: "s4", Iterate: &Iterate{Var: "w", Algorithm: AlgorithmDenyOverrides}}}})
	tree, err := NewTree(p.simplified, p.sets, p.pips)
	if err != nil {
		t.Fatal(err)
	}

	want := []Finding{
		{Where: `simplified "d"/"c"/"uri" > policy "sp1" > condition`, Form: FormJSONPath, Text: "resource.a[:]"},
		{Where: `set "s1" > policy "p1" > target`, Form: FormPIPType, Text: "subject.scope"},
		{Where: `set "s1" > policy "p1" > rule "r1" > condition`, Form: FormOperand, Text: "subject.x.y.z"},
		{Where: `set "s1" > set "s3" > set "s4"`, Form: FormNestedIterate, Text: "iterate var w"},
	}
	if got := tree.Unsupported(); !slices.Equal(got, want) {
		t.Errorf("Unsupported() =\n%v\nwant\n%v", got, want)
	}
}
