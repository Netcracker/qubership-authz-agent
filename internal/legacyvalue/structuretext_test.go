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

package legacyvalue

import (
	"strings"
	"testing"

	"authz-agent/internal/jsonvalue"
)

// The text a string compares a structure by prints a scalar member as Java
// text, and a nested member as compact JSON with its numbers as written. A
// number with a point or an exponent prints as Double.toString of its double,
// in plain notation where its digits reach past the point. The expected texts
// are what the specification's agent profile prints.
func TestStructureText(t *testing.T) {
	for _, tc := range []struct{ value, want string }{
		{`["x", null]`, `[x, null]`},
		{`[1.0, true]`, `[1.0, true]`},
		{`[1.50e1, -0.0, 100]`, `[15.0, -0.0, 100]`},
		{`[1e3, 1E3, -1e3]`, `[1000.0, 1000.0, -1000.0]`},
		{`{"k": 1e7}`, `{k=1.0E7}`},
		{`[5e0, 0e5, -0e0]`, `[5.0, 0.0, -0.0]`},
		{`[1.5e1, 1.50e1, 1.2345678912345679E8]`, `[15.0, 15.0, 123456789.12345679]`},
		{`[5.50, 1e-5, 0.001, 9999999.5, 1e7]`, `[5.5, 0.000010, 0.001, 9999999.5, 1.0E7]`},
		{`[1.2345678e7, 1.23456789e7, -1e-5, -1.2345678912345679E8]`,
			`[1.2345678E7, 12345678.9, -0.000010, -123456789.12345679]`},
		{`[1e-0, 5E-00, -0e-0, 1e+0, 1.0e-0, 10e-1]`, `[1.0, 5.0, -0.0, 1.0, 1.0, 1.0]`},
		{`[1e64, 1e65, 1e400]`, `[1.0E64, 1.0E65, Infinity]`},
		{`[1` + strings.Repeat("0", 64) + `, 1` + strings.Repeat("0", 65) + `]`,
			`[1` + strings.Repeat("0", 64) + `, 1` + strings.Repeat("0", 65) + `]`},
		{`[1e-65, 4.9e-324]`, `[0.` + strings.Repeat("0", 64) + `10, 0.` + strings.Repeat("0", 323) + `49]`},
		{`[1e9223372036854775807, 10e9223372036854775807]`, `[Infinity, Infinity]`},
		{`[1e-9223372036854775808, 0.1e-9223372036854775808]`, `[0.0, 0.0]`},
		{`[1e99999999999999999999]`, `[Infinity]`},
		{`[1e-99999999999999999999, -1e-400]`, `[0.0, -0.0]`},
		{`[["a"], "b"]`, `[["a"], b]`},
		{`{"k": {"b": "c"}}`, `{k={"b":"c"}}`},
		{`{"a": [1.0]}`, `{a=[1.0]}`},
		{`[]`, `[]`},
	} {
		v, err := jsonvalue.Decode([]byte(tc.value))
		if err != nil {
			t.Fatalf("jsonvalue.Decode(%s): %v", tc.value, err)
		}
		if got := StructureText(v); got != tc.want {
			t.Errorf("legacyvalue.StructureText(%s) = %q, want %q", tc.value, got, tc.want)
		}
	}
}
