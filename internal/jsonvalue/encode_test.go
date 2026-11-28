// Copyright 2024-2026 Netcracker Technology Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package jsonvalue

import (
	"bytes"
	"encoding/json"
	"math/rand/v2"
	"strings"
	"testing"
	"unicode/utf8"
)

// Encode writes a string of valid UTF-8 as encoding/json writes it with HTML
// escaping off, so a text that quotes a member compares equal to one
// encoding/json wrote.
func TestEncodeWritesAStringAsEncodingJSONDoes(t *testing.T) {
	inputs := []string{"", "abc", "\"q\" and \\", "<a href='x'>&amp;</a>", "tab\tnl\ncr\r",
		"\b\f\x00\x01\x1f\x7f", "  ", "Straße ✓ 😀", "line\u2028para\u2029"}
	rng := rand.New(rand.NewPCG(1, 2))
	for range 2000 {
		b := make([]byte, rng.IntN(12))
		for i := range b {
			b[i] = byte(rng.IntN(256))
		}
		if utf8.Valid(b) {
			inputs = append(inputs, string(b))
		}
	}
	for _, s := range inputs {
		var want bytes.Buffer
		enc := json.NewEncoder(&want)
		enc.SetEscapeHTML(false)
		if err := enc.Encode(s); err != nil {
			t.Fatalf("json.Encode(%q): %v", s, err)
		}
		if got := Encode(s); got != strings.TrimSuffix(want.String(), "\n") {
			t.Errorf("Encode(%q) = %s, want %s", s, got, want.String())
		}
	}
}

// Each byte of invalid UTF-8 becomes the character U+FFFD itself. The
// releases of encoding/json differ here: Go 1.27 writes the character, Go
// 1.26 the escape \ufffd.
func TestEncodeWritesAByteOfInvalidUTF8AsTheReplacementCharacter(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"bad \xff\xfe utf8", "\"bad \ufffd\ufffd utf8\""},
		{"\xed\xa0\x80 surrogate", "\"\ufffd\ufffd\ufffd surrogate\""},
		{"tail \xc3", "\"tail \ufffd\""},
	} {
		if got := Encode(tc.in); got != tc.want {
			t.Errorf("Encode(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
