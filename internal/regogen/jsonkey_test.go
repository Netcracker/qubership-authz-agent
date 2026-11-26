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
	"testing"

	"authz-agent/internal/jsonvalue"
)

func TestPyKey_IsSharedExactlyByTheValuesPythonFindsEqual(t *testing.T) {
	for _, tc := range []struct {
		name, a, b string
		equal      bool
	}{
		{"an int and the float of its value", `1`, `1.0`, true},
		{"true and 1", `true`, `1`, true},
		{"false and minus zero", `false`, `-0.0`, true},
		{"an exponent and the int it writes", `1e2`, `100`, true},
		{"two floats past the float range", `1e400`, `1e401`, true},
		{"an int no float holds and the nearest float", `9007199254740993`, `9007199254740993.0`, false},
		{"an int a float holds and that float", `9007199254740992`, `9007199254740992.0`, true},
		{"a power of ten no float holds and the nearest float", `100000000000000000000000`, `1e23`, false},
		{"a power of ten no float holds and the int of that float", `100000000000000000000000`, `99999999999999991611392`, false},
		{"a power of ten a float holds and that float", `10000000000000000000000`, `1e22`, true},
		{"two ints of more digits than a float holds", `123456789012345678901234567890`, `123456789012345678901234567891`, false},
		{"a number and its text", `1`, `"1"`, false},
		{"null and its text", `null`, `"null"`, false},
		{"objects whose members come in another order", `{"a": 1, "b": 2}`, `{"b": 2, "a": 1}`, true},
		{"objects whose nested members come in another order", `[{"x": {"a": 1, "b": 2}}]`, `[{"x": {"b": 2.0, "a": true}}]`, true},
		{"an object with one more member", `{"a": 1}`, `{"a": 1, "b": 2}`, false},
		{"lists whose elements come in another order", `[1, 2]`, `[2, 1]`, false},
		{"a key and a value that would splice into one text", `{"a": "b", "c": "d"}`, `{"a": "b\", \"c\": \"d"}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ka, kb := pyKey(mustDecode(t, tc.a)), pyKey(mustDecode(t, tc.b))
			if (ka == kb) != tc.equal {
				t.Errorf("pyKey(%s) = %q, pyKey(%s) = %q; want equal keys %v", tc.a, ka, tc.b, kb, tc.equal)
			}
		})
	}
}

func TestTypedKey_IsSharedExactlyByTheValuesOfOneTypeAndText(t *testing.T) {
	for _, tc := range []struct {
		name, a, b string
		equal      bool
	}{
		{"numbers written alike", `5.0`, `5.0`, true},
		{"numbers written differently", `5`, `5.0`, false},
		{"nested numbers written differently", `[5]`, `[5.0]`, false},
		{"true and 1", `true`, `1`, false},
		{"a number and its text", `5`, `"5"`, false},
		{"objects whose members come in another order", `{"a": 1, "b": 2}`, `{"b": 2, "a": 1}`, true},
		{"objects whose nested members come in another order", `[{"x": {"a": 1, "b": 2}}]`, `[{"x": {"b": 2, "a": 1}}]`, true},
		{"lists whose elements come in another order", `[1, 2]`, `[2, 1]`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ka, kb := typedKey(mustDecode(t, tc.a)), typedKey(mustDecode(t, tc.b))
			if (ka == kb) != tc.equal {
				t.Errorf("typedKey(%s) = %q, typedKey(%s) = %q; want equal keys %v", tc.a, ka, tc.b, kb, tc.equal)
			}
		})
	}
}

func TestDedupe_KeepsOneOfEqualObjectsWhateverTheOrderOfTheirMembers(t *testing.T) {
	for _, tc := range []struct{ name, list, want string }{
		{"top level", `[{"a": 1, "b": 2}, {"b": 2, "a": 1}]`, `[{"a": 1, "b": 2}]`},
		{"one level deeper", `[{"x": {"a": 1, "b": 2}}, {"x": {"b": 2, "a": 1}}]`, `[{"x": {"a": 1, "b": 2}}]`},
		{"numbers by value", `[5, 5.0, "5"]`, `[5, "5"]`},
		{"objects with other values", `[{"a": 1}, {"a": 2}]`, `[{"a": 1}, {"a": 2}]`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := jsonText(dedupe(mustDecode(t, tc.list).([]jsonvalue.Value)))
			if want := jsonText(mustDecode(t, tc.want)); got != want {
				t.Errorf("dedupe(%s) = %s, want %s", tc.list, got, want)
			}
		})
	}
}
