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
	"testing"
)

func TestDoubleText_PrintsAsJavaDoubleToString(t *testing.T) {
	tests := []struct {
		name string
		in   float64
		want string
	}{
		{"the smallest plain magnitude", 0.001, "0.001"},
		{"just below the plain range", 0.00099, "9.9E-4"},
		{"just below the largest plain magnitude", 9999999.999, "9999999.999"},
		{"the first exponent above the plain range", 1e7, "1.0E7"},
		{"an integer", 100, "100.0"},
		{"a negative fraction", -2.5, "-2.5"},
		{"seventeen digits", 0.30000000000000004, "0.30000000000000004"},
		{"a repeating fraction", 1.0 / 3, "0.3333333333333333"},
		{"a large power of two", 1 << 60, "1.152921504606847E18"},
		{"the smallest subnormal", 5e-324, "4.9E-324"},
		{"a subnormal with two digits", 2e-323, "2.0E-323"},
		{"a one-digit power of ten", 1e23, "1.0E23"},
		{"the largest double", math.MaxFloat64, "1.7976931348623157E308"},
		{"minus zero", math.Copysign(0, -1), "-0.0"},
		{"zero", 0, "0.0"},
		{"not a number", math.NaN(), "NaN"},
		{"positive infinity", math.Inf(1), "Infinity"},
		{"negative infinity", math.Inf(-1), "-Infinity"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := DoubleText(tt.in); got != tt.want {
				t.Errorf("DoubleText(%v) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}
