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
)

// BigDecimalText returns the text Java's new BigDecimal(s).toString() gives,
// and false where BigDecimal refuses s, as [ParseDecimal] does. Unlike a
// [Decimal], the text keeps the scale: 5.0 stays 5.0 and 1e7 becomes 1E+7.
// A number has plain notation while its scale is not negative and the exponent
// of its first digit is at least -6, so 0.000001 stays plain and 0.0000001
// becomes 1E-7. Zero has no sign.
func BigDecimalText(s string) (string, bool) {
	if _, ok := ParseDecimal(s); !ok {
		return "", false
	}
	rs := []rune(s)
	i := 0
	neg := false
	if rs[i] == '+' || rs[i] == '-' {
		neg = rs[i] == '-'
		i++
	}
	var digits []byte
	fracDigits := 0
	inFrac := false
	for ; i < len(rs) && rs[i] != 'e' && rs[i] != 'E'; i++ {
		if rs[i] == '.' {
			inFrac = true
			continue
		}
		digits = append(digits, digitValue(rs[i]))
		if inFrac {
			fracDigits++
		}
	}
	var exp int64
	if i < len(rs) {
		// ParseDecimal has checked that the exponent is in range.
		var b strings.Builder
		for _, r := range rs[i+1:] {
			if isDigit(r) {
				b.WriteByte(digitValue(r))
			} else {
				b.WriteRune(r)
			}
		}
		exp, _ = strconv.ParseInt(b.String(), 10, 64)
	}
	coef := strings.TrimLeft(string(digits), "0")
	if coef == "" {
		coef = "0"
		neg = false
	}
	scale := int64(fracDigits) - exp
	adjusted := -scale + int64(len(coef)) - 1
	var b strings.Builder
	if neg {
		b.WriteByte('-')
	}
	switch {
	case scale == 0:
		b.WriteString(coef)
	case scale > 0 && adjusted >= -6:
		if int64(len(coef)) > scale {
			b.WriteString(coef[:int64(len(coef))-scale])
			b.WriteByte('.')
			b.WriteString(coef[int64(len(coef))-scale:])
		} else {
			b.WriteString("0.")
			b.WriteString(strings.Repeat("0", int(scale-int64(len(coef)))))
			b.WriteString(coef)
		}
	default:
		b.WriteString(coef[:1])
		if len(coef) > 1 {
			b.WriteByte('.')
			b.WriteString(coef[1:])
		}
		b.WriteByte('E')
		if adjusted > 0 {
			b.WriteByte('+')
		}
		b.WriteString(strconv.FormatInt(adjusted, 10))
	}
	return b.String(), true
}
