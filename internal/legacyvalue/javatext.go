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
	"strconv"
	"strings"
	"unicode"

	"authz-agent/internal/jsonvalue"
)

// Fold returns the key under which two strings are equal exactly when Java's
// String.equalsIgnoreCase holds for them: each code point c becomes
// toLowerCase(toUpperCase(c)), with Unicode's simple, one-to-one case
// mappings, so the length in code points never changes.
func Fold(s string) string {
	return strings.Map(func(r rune) rune {
		return unicode.ToLower(unicode.ToUpper(r))
	}, s)
}

// NumberText returns the text the legacy service compares n by against a
// string: the digits of an integer, without leading zeros and with -0 as 0,
// and Double.toString of any other number, so 1e2 is 100.0.
func NumberText(n jsonvalue.Number) string {
	s := string(n)
	if isIntegerText(s) {
		neg := strings.HasPrefix(s, "-")
		digits := strings.TrimLeft(strings.TrimPrefix(s, "-"), "0")
		if digits == "" {
			return "0"
		}
		if neg {
			return "-" + digits
		}
		return digits
	}
	// A number beyond the range of a float64 parses as an infinity with
	// ErrRange, and Java reads it as Infinity too.
	f, _ := strconv.ParseFloat(s, 64)
	return jsonvalue.DoubleText(f)
}

// isIntegerText reports whether s is an optional minus and ASCII digits.
func isIntegerText(s string) bool {
	s = strings.TrimPrefix(s, "-")
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// Text returns Java's String.valueOf of v: an object as {k=v, w=x} in member
// order, a list as [v, w], null as null, a number by [NumberText], and a string
// as itself. It is the text a string equals a list or an object by.
func Text(v jsonvalue.Value) string {
	var b strings.Builder
	writeText(&b, v)
	return b.String()
}

func writeText(b *strings.Builder, v jsonvalue.Value) {
	switch x := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		b.WriteString(strconv.FormatBool(x))
	case jsonvalue.Number:
		b.WriteString(NumberText(x))
	case string:
		b.WriteString(x)
	case []jsonvalue.Value:
		b.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				b.WriteString(", ")
			}
			writeText(b, e)
		}
		b.WriteByte(']')
	case *jsonvalue.Object:
		b.WriteByte('{')
		for i, k := range x.Keys() {
			if i > 0 {
				b.WriteString(", ")
			}
			b.WriteString(k)
			b.WriteByte('=')
			m, _ := x.Get(k)
			writeText(b, m)
		}
		b.WriteByte('}')
	}
}
