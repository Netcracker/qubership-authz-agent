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

// listOfOnes returns a list of n numbers 1, whose weight is 1 + 2n.
func listOfOnes(t *testing.T, n int) jsonvalue.Value {
	t.Helper()
	doc := make([]byte, 0, 2*n+1)
	doc = append(doc, '[')
	for i := range n {
		if i > 0 {
			doc = append(doc, ',')
		}
		doc = append(doc, '1')
	}
	doc = append(doc, ']')
	v, err := jsonvalue.Decode(doc)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	return v
}

// The budget of a document of weight W admits work up to 4W + 4096, whether
// the work arrives in one charge or in many, which make budget weigh the
// document several times.
func TestBudget_AdmitsWorkUpToFourTimesTheWeightPlusTheFloor(t *testing.T) {
	// A list of 10000 ones weighs 20001, so it admits 4*20001 + 4096 = 84100.
	const limit = 84100
	tests := []struct {
		name  string
		step  int
		total int
		want  bool
	}{
		{"one charge at the limit", limit, limit, true},
		{"one charge past the limit", limit + 1, limit + 1, false},
		{"single units up to the limit", 1, limit, true},
		{"single units past the limit", 1, limit + 1, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := budget{doc: listOfOnes(t, 10000)}
			got := true
			for spent := 0; spent < tt.total && got; spent += tt.step {
				got = b.charge(tt.step)
			}
			if got != tt.want {
				t.Errorf("charge of %d in steps of %d = %v, want %v", tt.total, tt.step, got, tt.want)
			}
		})
	}
}

// Work just past the floor weighs only the start of a large document, not all
// of it.
func TestBudget_WeighsTheDocumentOnlyAsFarAsTheWorkNeeds(t *testing.T) {
	b := budget{doc: listOfOnes(t, 1000000)}
	if !b.charge(budgetFloor + 100) {
		t.Fatalf("charge(%d) over a list of a million values = false, want true", budgetFloor+100)
	}
	if b.weighed || b.docWeight > 1000 {
		t.Errorf("after charge(%d), docWeight = %d, weighed = %v; want a bound under 1000 of a weight of 2000001",
			budgetFloor+100, b.docWeight, b.weighed)
	}
}

// chargeWeight admits the weight of a value up to the same limit as charge,
// also where it has to weigh more of the document after reading part of the
// value.
func TestBudget_ChargeWeightAdmitsUpToTheSameLimit(t *testing.T) {
	// A list of 10000 ones weighs 20001: work of 3*20001 + 4096 = 64099 leaves
	// exactly the weight of the list.
	tests := []struct {
		name  string
		spent int
		want  bool
	}{
		{"the weight of the document at the limit", 64099, true},
		{"the weight of the document past the limit", 64100, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc := listOfOnes(t, 10000)
			b := budget{doc: doc}
			if !b.charge(tt.spent) {
				t.Fatalf("charge(%d) = false, want true", tt.spent)
			}
			if got := b.chargeWeight(doc); got != tt.want {
				t.Errorf("chargeWeight(document) after charge(%d) = %v, want %v", tt.spent, got, tt.want)
			}
		})
	}
}
