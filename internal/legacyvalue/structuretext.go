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

	"authz-agent/internal/jsonvalue"
)

// StructureText is the text a string compares a list or an object by under
// every comparing operator (ADR-0083 R8): the members in document order,
// as [v, w] or {k=v}; a scalar member as its Java text, with a number as
// structureNumberText prints it; and a member that is itself a list or an
// object as [jsonvalue.Encode] writes it. For a scalar v it is the text of v
// as such a member.
func StructureText(v jsonvalue.Value) string {
	member := func(x jsonvalue.Value) string {
		switch x := x.(type) {
		case []jsonvalue.Value, *jsonvalue.Object:
			return jsonvalue.Encode(x)
		case nil:
			return "null"
		case bool:
			return strconv.FormatBool(x)
		case jsonvalue.Number:
			return structureNumberText(x)
		case string:
			return x
		}
		return ""
	}
	var parts []string
	switch v := v.(type) {
	case []jsonvalue.Value:
		for _, x := range v {
			parts = append(parts, member(x))
		}
		return "[" + strings.Join(parts, ", ") + "]"
	case *jsonvalue.Object:
		for _, k := range v.Keys() {
			x, _ := v.Get(k)
			parts = append(parts, k+"="+member(x))
		}
		return "{" + strings.Join(parts, ", ") + "}"
	}
	return member(v)
}

// structureNumberText is the text of a number that is a member of a list or
// an object in [StructureText]. An integer without a point or an exponent is
// its digits. Any other number with the double d is Java's BigDecimal.toString
// of new BigDecimal(Double.toString(d)) when that BigDecimal has a positive
// scale, and Double.toString(d) otherwise: 1.0 is 1.0, 5.50 is 5.5, 1e3 is
// 1000.0, 1e-6 is 0.0000010, 1e-7 is 1.0E-7, and 1.2345678912345679E8 is
// 123456789.12345679, while 1e7 stays 1.0E7. -0.0 is 0.0, a choice no golden
// confirms.
func structureNumberText(n jsonvalue.Number) string {
	text := NumberText(n)
	mantissa, exp, _ := strings.Cut(text, "E")
	_, frac, ok := strings.Cut(mantissa, ".")
	if !ok {
		// The digits of an integer, or Infinity.
		return text
	}
	// Double.toString writes the exponent as a decimal integer, so Atoi
	// reads it without an error.
	e := 0
	if exp != "" {
		e, _ = strconv.Atoi(exp)
	}
	if len(frac) <= e {
		// The scale is not positive.
		return text
	}
	decimal, _ := jsonvalue.BigDecimalText(text)
	return decimal
}
