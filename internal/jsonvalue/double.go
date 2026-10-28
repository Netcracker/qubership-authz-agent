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
	"math"
	"strconv"
	"strings"
)

// DoubleText returns x as Java's Double.toString prints it: plain notation for
// a magnitude from 10^-3 up to but not including 10^7, otherwise one digit,
// a point, and an exponent, as in 1.0E7 and 1.5E-4. The digits are the
// shortest that read back as x, and at least two, as JDK 19 and later choose
// them, so the smallest subnormal prints as 4.9E-324.
func DoubleText(x float64) string {
	switch {
	case math.IsNaN(x):
		return "NaN"
	case math.IsInf(x, 1):
		return "Infinity"
	case math.IsInf(x, -1):
		return "-Infinity"
	case x == 0:
		if math.Signbit(x) {
			return "-0.0"
		}
		return "0.0"
	}
	// 'e' with precision -1 gives the shortest digits as d.ddde±XX. Where
	// they are one digit, Java prints the two-digit decimal nearest to x
	// instead, which differs only for a subnormal: 4.9E-324, not 5.0E-324.
	sci := strconv.FormatFloat(math.Abs(x), 'e', -1, 64)
	if two := strconv.FormatFloat(math.Abs(x), 'e', 1, 64); !strings.Contains(sci, ".") {
		if f, err := strconv.ParseFloat(two, 64); err == nil && f == math.Abs(x) {
			sci = two
		}
	}
	mant, expText, _ := strings.Cut(sci, "e")
	// The mantissa of a nonzero x starts with a nonzero digit.
	digits := strings.TrimRight(strings.Replace(mant, ".", "", 1), "0")
	e10, _ := strconv.Atoi(expText)
	sign := ""
	if x < 0 {
		sign = "-"
	}
	if abs := math.Abs(x); abs >= 1e-3 && abs < 1e7 {
		var ip, fp string
		if e10 >= 0 {
			if len(digits) > e10+1 {
				ip, fp = digits[:e10+1], digits[e10+1:]
			} else {
				ip = digits + strings.Repeat("0", e10+1-len(digits))
			}
		} else {
			ip, fp = "0", strings.Repeat("0", -e10-1)+digits
		}
		if fp == "" {
			fp = "0"
		}
		return sign + ip + "." + fp
	}
	fp := digits[1:]
	if fp == "" {
		fp = "0"
	}
	return sign + digits[:1] + "." + fp + "E" + strconv.Itoa(e10)
}
