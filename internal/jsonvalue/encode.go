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

package jsonvalue

import (
	"strconv"
	"strings"
	"unicode/utf8"
)

// Encode returns v as compact JSON: each number as the document wrote it, and
// the members of an object in document order.
func Encode(v Value) string {
	var b strings.Builder
	writeJSONText(&b, v)
	return b.String()
}

func writeJSONText(b *strings.Builder, v Value) {
	switch v := v.(type) {
	case []Value:
		b.WriteByte('[')
		for i, x := range v {
			if i > 0 {
				b.WriteByte(',')
			}
			writeJSONText(b, x)
		}
		b.WriteByte(']')
	case *Object:
		b.WriteByte('{')
		for i, k := range v.Keys() {
			if i > 0 {
				b.WriteByte(',')
			}
			x, _ := v.Get(k)
			writeJSONString(b, k)
			b.WriteByte(':')
			writeJSONText(b, x)
		}
		b.WriteByte('}')
	case Number:
		b.WriteString(string(v))
	case string:
		writeJSONString(b, v)
	case bool:
		b.WriteString(strconv.FormatBool(v))
	default:
		b.WriteString("null")
	}
}

// writeJSONString writes s as a JSON string the way encoding/json does with
// HTML escaping off: a quote, a backslash, and a control character escaped,
// and U+2028 and U+2029 as \u2028 and \u2029. A byte of invalid UTF-8
// becomes the character U+FFFD, whichever escape the encoding/json of the
// toolchain would write.
func writeJSONString(b *strings.Builder, s string) {
	const hex = "0123456789abcdef"
	b.WriteByte('"')
	for i := 0; i < len(s); {
		c := s[i]
		if c < utf8.RuneSelf {
			switch {
			case c == '"' || c == '\\':
				b.WriteByte('\\')
				b.WriteByte(c)
			case c >= 0x20:
				b.WriteByte(c)
			case c == '\b':
				b.WriteString(`\b`)
			case c == '\f':
				b.WriteString(`\f`)
			case c == '\n':
				b.WriteString(`\n`)
			case c == '\r':
				b.WriteString(`\r`)
			case c == '\t':
				b.WriteString(`\t`)
			default:
				b.WriteString(`\u00`)
				b.WriteByte(hex[c>>4])
				b.WriteByte(hex[c&0xF])
			}
			i++
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && size == 1:
			b.WriteRune(utf8.RuneError)
		case r == '\u2028':
			b.WriteString(`\u2028`)
		case r == '\u2029':
			b.WriteString(`\u2029`)
		default:
			b.WriteString(s[i : i+size])
		}
		i += size
	}
	b.WriteByte('"')
}
