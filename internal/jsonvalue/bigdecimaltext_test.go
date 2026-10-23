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

import "testing"

// The expected texts are what Java's new BigDecimal(in).toString() printed.
func TestBigDecimalText_PrintsAsJavaBigDecimalToString(t *testing.T) {
	tests := []struct {
		name, in, want string
	}{
		{"an integer", "5", "5"},
		{"minus zero", "-0", "0"},
		{"zero with a scale", "0.0", "0.0"},
		{"a trailing zero stays", "5.0", "5.0"},
		{"trailing zeros stay", "1.50", "1.50"},
		{"a leading zero goes", "010", "10"},
		{"a positive exponent", "1e7", "1E+7"},
		{"an exponent with a plus", "1E+2", "1E+2"},
		{"a negative exponent", "1e-7", "1E-7"},
		{"the smallest plain magnitude", "0.000001", "0.000001"},
		{"just below the plain magnitude", "0.0000001", "1E-7"},
		{"a trailing zero at the plain boundary", "0.0000010", "0.0000010"},
		{"an exponent that cancels the fraction", "123.456e3", "123456"},
		{"a negative fraction with an exponent", "-1.5e-10", "-1.5E-10"},
		{"beyond the double range", "1e400", "1E+400"},
		{"zero with a positive exponent", "0e5", "0E+5"},
		{"zero with a negative exponent", "0E-10", "0E-10"},
		{"minus zero with a scale", "-0.0", "0.0"},
		{"beyond the long range", "12345678901234567890", "12345678901234567890"},
		{"Arabic-Indic digits", "٣.٥", "3.5"},
		{"a plus sign", "+7", "7"},
		{"no integer digits", ".5", "0.5"},
		{"no fraction digits", "5.", "5"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, ok := BigDecimalText(tt.in); !ok || got != tt.want {
				t.Errorf("BigDecimalText(%q) = %q, %v, want %q, true", tt.in, got, ok, tt.want)
			}
		})
	}
}

func TestBigDecimalText_RefusesWhatBigDecimalRefuses(t *testing.T) {
	for _, s := range []string{"", "NaN", "1_0", " 5", "0x10"} {
		if got, ok := BigDecimalText(s); ok {
			t.Errorf("BigDecimalText(%q) = %q, want a refusal", s, got)
		}
	}
}
