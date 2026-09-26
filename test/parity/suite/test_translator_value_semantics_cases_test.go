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

//go:build integration

package paritysuite

import "encoding/json"

// How equality and membership treat a value that is not a string in the case the
// literal is written in. The agent's own condition parser accepts every condition
// below and no golden records the answer.
//
// Two recorded answers look like they disagree about numbers, and the vn cases are
// written to settle them rather than to add a third. c1-number-literal/float
// records resource.n == 5 as false for the attribute 5.0;
// c11-decimal-number-equals/trailing-zero records resource.n == 5.5 as true for the
// attribute 5.50. One rule already explains both: parse the attribute to a double,
// then compare the string forms. 5.50 renders as "5.5" and equals the literal,
// while 5.0 renders as "5.0" and does not equal "5".
//
// vn1/two-decimal-places (5.00), vn1/exponent (5e0) and vn5 (1e2 against the
// literal 100) are the requests that tell that reading from the one where the
// literal's own form picks the comparison: under the double-then-string rule all
// three are true, and under the second only the ones whose literal is written the
// same way. vn2, a fractional literal against an integer attribute, and vn4, the
// negated side, carry the remaining columns.
//
// Each case carries the request a working operator answers true, because a
// condition access-control accepts and never evaluates answers false to every
// request; resource['x'] and MATCH against an attribute are already recorded as
// behaving that way (j7, a2).
//
// The cases live in their own test function so that a recording run can be filtered
// to them and leave every golden already committed alone.
func (s *ParitySuite) TestTranslatorValueSemanticsCases() {
	s.runIsolatedCases([]isolatedCase{
		// Numbers. c1 records the integer literal against 5, "5" and 5.0; these
		// cases carry the forms it left out, and each one repeats an answer c1 or
		// c11 already has as its control.
		{id: "vn1-integer-literal-against-written-decimals", resourceType: "PARITY_SUITE_VAL_VN1", condition: "resource.n == 5", requests: []isolatedRequest{
			{name: "integer", resource: map[string]any{"id": "val-vn1", "n": json.Number("5")}},
			{name: "one-decimal-place-as-a-string", resource: map[string]any{"id": "val-vn1", "n": "5.0"}},
			{name: "two-decimal-places", resource: map[string]any{"id": "val-vn1", "n": json.Number("5.00")}},
			{name: "exponent", resource: map[string]any{"id": "val-vn1", "n": json.Number("5e0")}},
		}},
		{id: "vn2-fractional-literal-against-an-integer", resourceType: "PARITY_SUITE_VAL_VN2", condition: "resource.n == 5.0", requests: []isolatedRequest{
			{name: "one-decimal-place", resource: map[string]any{"id": "val-vn2", "n": json.Number("5.0")}},
			{name: "integer", resource: map[string]any{"id": "val-vn2", "n": json.Number("5")}},
			{name: "two-decimal-places", resource: map[string]any{"id": "val-vn2", "n": json.Number("5.00")}},
			{name: "integer-as-a-string", resource: map[string]any{"id": "val-vn2", "n": "5"}},
			{name: "one-decimal-place-as-a-string", resource: map[string]any{"id": "val-vn2", "n": "5.0"}},
		}},
		{id: "vn3-fractional-literal-against-longer-decimals", resourceType: "PARITY_SUITE_VAL_VN3", condition: "resource.n == 5.5", requests: []isolatedRequest{
			{name: "one-decimal-place", resource: map[string]any{"id": "val-vn3", "n": json.Number("5.5")}},
			{name: "two-decimal-places-as-a-string", resource: map[string]any{"id": "val-vn3", "n": "5.50"}},
			{name: "four-decimal-places", resource: map[string]any{"id": "val-vn3", "n": json.Number("5.5000")}},
		}},
		// The negated side of the same rule, which the translator has to project
		// the same way and which no recorded case covers.
		{id: "vn4-integer-literal-negated", resourceType: "PARITY_SUITE_VAL_VN4", condition: "resource.n != 5", requests: []isolatedRequest{
			{name: "integer", resource: map[string]any{"id": "val-vn4", "n": json.Number("5")}},
			{name: "one-decimal-place", resource: map[string]any{"id": "val-vn4", "n": json.Number("5.0")}},
			{name: "integer-as-a-string", resource: map[string]any{"id": "val-vn4", "n": "5"}},
			{name: "another-integer", resource: map[string]any{"id": "val-vn4", "n": json.Number("6")}},
		}},
		{id: "vn5-exponent-against-a-plain-integer", resourceType: "PARITY_SUITE_VAL_VN5", condition: "resource.n == 100", requests: []isolatedRequest{
			{name: "plain-integer", resource: map[string]any{"id": "val-vn5", "n": json.Number("100")}},
			{name: "exponent", resource: map[string]any{"id": "val-vn5", "n": json.Number("1e2")}},
			{name: "exponent-as-a-string", resource: map[string]any{"id": "val-vn5", "n": "1e2"}},
		}},
		// c2 records the literal 9007199254740993 as unequal to its neighbor below,
		// so equality survives the first integer a float64 cannot hold. This is the
		// same pair with the literal on the other side, which a comparison that
		// rounds one operand only would answer differently.
		{id: "vn6-integer-past-float-precision", resourceType: "PARITY_SUITE_VAL_VN6", condition: "resource.n == 9007199254740992", requests: []isolatedRequest{
			{name: "exact", resource: map[string]any{"id": "val-vn6", "n": json.Number("9007199254740992")}},
			{name: "neighbour-above", resource: map[string]any{"id": "val-vn6", "n": json.Number("9007199254740993")}},
			{name: "exact-as-a-string", resource: map[string]any{"id": "val-vn6", "n": "9007199254740992"}},
		}},
		// Relational operators compare numerically, so the string "10" is greater
		// than 5 (c3, in the round 2 semantics cases). These are the operands where a
		// numeric comparison has no value to work with, each sent on its own so that
		// one refusal does not mask the next. numeric-string-above is the control.
		{id: "vn7-relational-over-a-non-number", resourceType: "PARITY_SUITE_VAL_VN7", condition: "resource.n > 5", requests: []isolatedRequest{
			{name: "numeric-string-above", resource: map[string]any{"id": "val-vn7", "n": "10"}},
			{name: "non-numeric-string", resource: map[string]any{"id": "val-vn7", "n": "abc"}},
			{name: "boolean", resource: map[string]any{"id": "val-vn7", "n": true}},
			{name: "null", resource: map[string]any{"id": "val-vn7", "n": nil}},
			{name: "collection", resource: map[string]any{"id": "val-vn7", "n": []any{json.Number("6")}}},
		}},
		{id: "vn8-relational-over-negative-strings", resourceType: "PARITY_SUITE_VAL_VN8", condition: "resource.n > -5", requests: []isolatedRequest{
			{name: "negative-string-above", resource: map[string]any{"id": "val-vn8", "n": "-4"}},
			{name: "negative-string-below", resource: map[string]any{"id": "val-vn8", "n": "-10"}},
		}},

		// Case outside ASCII. Two strings differing only in ASCII case are equal
		// (c5-string-equals-other-case, in the round 2 semantics cases), and that
		// leaves two readings: the comparison ignores case, or both operands are
		// lower-cased first. vc1 separates them, because the long s upper-cases to S
		// and lower-cases to itself. vc2 and vc3 add the pairs whose two cases are
		// not the same length and whose lower case carries a combining mark.
		{id: "vc1-long-s-against-ascii-s", resourceType: "PARITY_SUITE_VAL_VC1", condition: "resource.x == 's'", requests: []isolatedRequest{
			{name: "ascii-lower-case", resource: map[string]any{"id": "val-vc1", "x": "s"}},
			{name: "ascii-upper-case", resource: map[string]any{"id": "val-vc1", "x": "S"}},
			{name: "long-s", resource: map[string]any{"id": "val-vc1", "x": "ſ"}},
		}},
		{id: "vc2-sharp-s-against-a-pair-of-s", resourceType: "PARITY_SUITE_VAL_VC2", condition: "resource.x == 'ss'", requests: []isolatedRequest{
			{name: "lower-case-pair", resource: map[string]any{"id": "val-vc2", "x": "ss"}},
			{name: "upper-case-pair", resource: map[string]any{"id": "val-vc2", "x": "SS"}},
			{name: "sharp-s", resource: map[string]any{"id": "val-vc2", "x": "ß"}},
		}},
		{id: "vc3-dotted-and-dotless-i", resourceType: "PARITY_SUITE_VAL_VC3", condition: "resource.x == 'i'", requests: []isolatedRequest{
			{name: "ascii-lower-case", resource: map[string]any{"id": "val-vc3", "x": "i"}},
			{name: "ascii-upper-case", resource: map[string]any{"id": "val-vc3", "x": "I"}},
			{name: "capital-i-with-dot-above", resource: map[string]any{"id": "val-vc3", "x": "İ"}},
			{name: "dotless-lower-case-i", resource: map[string]any{"id": "val-vc3", "x": "ı"}},
		}},
		{id: "vc4-cyrillic-case", resourceType: "PARITY_SUITE_VAL_VC4", condition: "resource.x == 'я'", requests: []isolatedRequest{
			{name: "lower-case", resource: map[string]any{"id": "val-vc4", "x": "я"}},
			{name: "upper-case", resource: map[string]any{"id": "val-vc4", "x": "Я"}},
		}},
		{id: "vc5-cyrillic-case-under-in", resourceType: "PARITY_SUITE_VAL_VC5", condition: "resource.x IN 'я', 'other'", requests: []isolatedRequest{
			{name: "lower-case", resource: map[string]any{"id": "val-vc5", "x": "я"}},
			{name: "upper-case", resource: map[string]any{"id": "val-vc5", "x": "Я"}},
		}},
		{id: "vc6-cyrillic-case-under-contains", resourceType: "PARITY_SUITE_VAL_VC6", condition: "resource.tags CONTAINS 'я'", requests: []isolatedRequest{
			{name: "lower-case-element", resource: map[string]any{"id": "val-vc6", "tags": []string{"я"}}},
			{name: "upper-case-element", resource: map[string]any{"id": "val-vc6", "tags": []string{"Я"}}},
		}},

		// Operands whose JSON type is not the literal's. A boolean equals its own
		// string form and two strings equal each other across ASCII case, so vt2
		// asks whether the two rules compose.
		{id: "vt1-number-against-a-string-literal", resourceType: "PARITY_SUITE_VAL_VT1", condition: "resource.n == '5'", requests: []isolatedRequest{
			{name: "string", resource: map[string]any{"id": "val-vt1", "n": "5"}},
			{name: "number", resource: map[string]any{"id": "val-vt1", "n": json.Number("5")}},
			{name: "number-with-a-decimal-place", resource: map[string]any{"id": "val-vt1", "n": json.Number("5.0")}},
		}},
		{id: "vt2-boolean-against-an-upper-case-string-literal", resourceType: "PARITY_SUITE_VAL_VT2", condition: "resource.b == 'TRUE'", requests: []isolatedRequest{
			{name: "string-in-the-same-case", resource: map[string]any{"id": "val-vt2", "b": "TRUE"}},
			{name: "string-in-lower-case", resource: map[string]any{"id": "val-vt2", "b": "true"}},
			{name: "boolean-true", resource: map[string]any{"id": "val-vt2", "b": true}},
			{name: "boolean-false", resource: map[string]any{"id": "val-vt2", "b": false}},
		}},
		{id: "vt3-contains-over-elements-in-another-case", resourceType: "PARITY_SUITE_VAL_VT3", condition: "resource.tags CONTAINS 'RED'", requests: []isolatedRequest{
			{name: "element-in-the-same-case", resource: map[string]any{"id": "val-vt3", "tags": []string{"RED"}}},
			{name: "element-in-lower-case", resource: map[string]any{"id": "val-vt3", "tags": []string{"red"}}},
		}},
		{id: "vt4-contains-over-numbers", resourceType: "PARITY_SUITE_VAL_VT4", condition: "resource.ns CONTAINS 5", requests: []isolatedRequest{
			{name: "number-element", resource: map[string]any{"id": "val-vt4", "ns": []any{json.Number("5")}}},
			{name: "string-element", resource: map[string]any{"id": "val-vt4", "ns": []string{"5"}}},
			{name: "element-with-a-decimal-place", resource: map[string]any{"id": "val-vt4", "ns": []any{json.Number("5.0")}}},
		}},
		// Whether CONTAINS over an object reads its keys, its values, or neither.
		// Both object requests can be false at once, so the control is the third
		// one: CONTAINS over a collection holding the value is recorded as true
		// (l5), and a false answer there means the attribute path rather than the
		// object.
		{id: "vt5-contains-over-an-object", resourceType: "PARITY_SUITE_VAL_VT5", condition: "resource.o CONTAINS 'k'", requests: []isolatedRequest{
			{name: "a-collection-holding-the-value", resource: map[string]any{"id": "val-vt5", "o": []string{"k"}}},
			{name: "an-object-with-the-value-as-a-key", resource: map[string]any{"id": "val-vt5", "o": map[string]any{"k": "v"}}},
			{name: "an-object-with-the-value-as-a-value", resource: map[string]any{"id": "val-vt5", "o": map[string]any{"v": "k"}}},
		}},
		// A list literal whose members have three different types. l8 records a
		// number list; this adds the mixed one, and asks which member each attribute
		// finds.
		{id: "vt6-in-a-list-of-mixed-types", resourceType: "PARITY_SUITE_VAL_VT6", condition: "resource.x IN 'a', 5, TRUE", requests: []isolatedRequest{
			{name: "the-string-member", resource: map[string]any{"id": "val-vt6", "x": "a"}},
			{name: "the-number-member", resource: map[string]any{"id": "val-vt6", "x": json.Number("5")}},
			{name: "the-boolean-member", resource: map[string]any{"id": "val-vt6", "x": true}},
			{name: "no-member", resource: map[string]any{"id": "val-vt6", "x": "b"}},
		}},
	})
}
