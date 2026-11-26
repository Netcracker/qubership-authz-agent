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
// its digits; any other number is Double.toString of the double it reads,
// written in plain notation where its digits reach past the point: 1.0 is
// 1.0, 5.50 is 5.5, 1e3 is 1000.0, 1e-5 is 0.000010, and
// 1.2345678912345679E8 is 123456789.12345679, while 1e7 stays 1.0E7; -0.0
// keeps its sign. These are the texts the specification's agent profile
// prints.
func structureNumberText(n jsonvalue.Number) string {
	text := NumberText(n)
	mantissa, exp, ok := strings.Cut(text, "E")
	if !ok {
		return text
	}
	// Double.toString writes the exponent of a finite double, which lies
	// between -324 and 308, so the plain text stays under 350 bytes.
	e, _ := strconv.Atoi(exp)
	sign := ""
	if m, neg := strings.CutPrefix(mantissa, "-"); neg {
		sign, mantissa = "-", m
	}
	lead, frac, _ := strings.Cut(mantissa, ".")
	if len(frac) <= e {
		return text
	}
	digits, point := lead+frac, len(lead)+e
	if point <= 0 {
		return sign + "0." + strings.Repeat("0", -point) + digits
	}
	return sign + digits[:point] + "." + digits[point:]
}
