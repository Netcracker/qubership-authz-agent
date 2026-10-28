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
	"fmt"
	"math/rand/v2"
	"regexp"
	"strings"
	"testing"
)

// attributeTokenOracle is the legacy attribute token rule written as a regular
// expression and matched leftmost-longest. It is correct and quadratic over a
// whole condition, so the scanner replaces it and the test compares the two.
var attributeTokenOracle = func() *regexp.Regexp {
	c := `[A-Za-z0-9_$@,:?*(=)\-.~></&|!']`
	x := `[A-Za-z0-9_$@,:?*(=)\-.~></&|!' ]`
	re := regexp.MustCompile(`^[A-Za-z_]` + c + `*(?:(?:\[` + x + `*)*(?:` + x + `+\])+` + c + `*)*`)
	re.Longest()
	return re
}()

func TestAttrScannerMatchesTheLongestAttributeToken(t *testing.T) {
	t.Parallel()

	cases := []string{
		"true,false IN",
		"FALSE, true",
		"subject.permissionScope.a[0] == 1",
		"resource.items[?(@.k == 'v')].length() == 1",
		"resource.a[0] == resource.b[1]",
		"resource.a == 1 OR resource.b == 'x]'",
		"a b]c]",
		"a]]",
		"a[]",
		"a[[x]]",
		"a[ [x] ] y",
	}
	for _, s := range cases {
		checkAttrScanner(t, s)
	}

	const alphabet = "ab1_.,' []%"
	seed := rand.Uint64()
	r := rand.New(rand.NewPCG(seed, 0))
	for range 20000 {
		b := make([]byte, r.IntN(16))
		for i := range b {
			b[i] = alphabet[r.IntN(len(alphabet))]
		}
		if !checkAttrScanner(t, string(b)) {
			t.Fatalf("seed %d", seed)
		}
	}
}

func checkAttrScanner(t *testing.T, s string) bool {
	t.Helper()
	a := newAttrScanner(s)
	for i := range len(s) + 1 {
		if got, want := a.tokenLen(i), len(attributeTokenOracle.FindString(s[i:])); got != want {
			t.Errorf("tokenLen(%d) of %q = %d, want %d", i, s, got, want)
			return false
		}
	}
	return true
}

// A condition of n comparisons joined by OR used to take time quadratic in n:
// each operand's longest-token match read the rest of the condition. The time
// per comparison reported for each size has to stay flat.
func BenchmarkParseConditionChain(b *testing.B) {
	for _, n := range []int{512, 1024, 2048, 4096} {
		text := strings.TrimSuffix(strings.Repeat("resource.a == 'v' OR ", n), " OR ")
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			for b.Loop() {
				if _, err := ParseCondition(text, PlaceRuleCondition, ""); err != nil {
					b.Fatal(err)
				}
			}
			b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N)/float64(n), "ns/comparison")
		})
	}
}
