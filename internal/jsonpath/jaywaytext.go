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
	"fmt"
	"strings"
	"unicode"
	"unicode/utf16"

	"authz-agent/internal/jsonvalue"
)

// unescape decodes the escapes of a text as Jayway's Utils.unescape does: \\,
// \', \", \r, \f, \t, \n, and \b stand for their characters, \u and four
// UTF-16 chars that Integer.parseInt reads in base 16 stand for one char, any
// other escaped char stands for itself, a trailing backslash stays, and a \u
// cut short by the end of the text is dropped. It returns an error where
// Jayway throws, for a \u it cannot read, and where the result holds half of
// a surrogate pair, which a Go string cannot hold the way a Java string does.
func unescape(s string) (string, error) {
	if !strings.Contains(s, `\`) {
		return s, nil
	}
	var out, hex []uint16
	slash, inHex := false, false
	for _, u := range utf16.Encode([]rune(s)) {
		switch {
		case inHex:
			hex = append(hex, u)
			if len(hex) == 4 {
				v, ok := parseHex(hex)
				if !ok {
					return "", fmt.Errorf(`\u%s`, string(utf16.Decode(hex)))
				}
				out = append(out, uint16(v))
				hex, inHex, slash = hex[:0], false, false
			}
		case slash:
			slash = false
			switch u {
			case 'r':
				out = append(out, '\r')
			case 'f':
				out = append(out, '\f')
			case 't':
				out = append(out, '\t')
			case 'n':
				out = append(out, '\n')
			case 'b':
				out = append(out, '\b')
			case 'u':
				inHex = true
			default:
				out = append(out, u)
			}
		case u == '\\':
			slash = true
		default:
			out = append(out, u)
		}
	}
	if slash {
		out = append(out, '\\')
	}
	for i := 0; i < len(out); i++ {
		switch {
		case !utf16.IsSurrogate(rune(out[i])):
		case out[i] < 0xDC00 && i+1 < len(out) && out[i+1] >= 0xDC00 && out[i+1] <= 0xDFFF:
			i++
		default:
			return "", fmt.Errorf("half of a surrogate pair in %q", s)
		}
	}
	return string(utf16.Decode(out)), nil
}

// parseHex reads chars as Java's Integer.parseInt(s, 16) does: an optional
// sign, then digits Character.digit reads in base 16, decimal digits of any
// script among them.
func parseHex(chars []uint16) (int, bool) {
	neg := false
	if chars[0] == '+' || chars[0] == '-' {
		neg = chars[0] == '-'
		chars = chars[1:]
	}
	v := 0
	for _, c := range chars {
		d := hexDigit(rune(c))
		if d < 0 {
			return 0, false
		}
		v = v*16 + d
	}
	if neg {
		v = -v
	}
	return v, true
}

// hexDigit returns the value Character.digit(c, 16) gives c, or -1.
func hexDigit(c rune) int {
	switch {
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	case c >= 0xFF41 && c <= 0xFF46: // fullwidth a to f
		return int(c-0xFF41) + 10
	case c >= 0xFF21 && c <= 0xFF26: // fullwidth A to F
		return int(c-0xFF21) + 10
	case unicode.IsDigit(c):
		// A one-digit Decimal prints as its ASCII digit.
		d, _ := jsonvalue.ParseDecimal(string(c))
		return int(d.String()[0] - '0')
	}
	return -1
}

// quotedText returns the text between the quotes of a bracket key, a filter
// literal, or a list item, unescaped. It refuses a text that ends in an odd number of
// backslashes, as Jayway reads its closing quote as escaped.
func quotedText(raw string) (string, error) {
	n := len(raw) - len(strings.TrimRight(raw, `\`))
	if n%2 == 1 {
		return "", fmt.Errorf("escaped closing quote in '%s'", raw)
	}
	return unescape(raw)
}
