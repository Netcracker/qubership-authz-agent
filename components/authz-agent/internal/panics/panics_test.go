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

package panics

import (
	"fmt"
	"strings"
	"testing"
)

// catching runs f and returns what Catch makes of its panic.
func catching(f func()) (r *Recovered) {
	defer func() { r = Catch(recover()) }()
	f()
	return nil
}

func explicitPanic() { panic("boom") }

func callsExplicitPanic() { explicitPanic() }

func noCounter() *int { return nil }

func nilDereference() { *noCounter()++ }

func TestCatchNamesTheFunctionThatPanicked(t *testing.T) {
	for _, tc := range []struct {
		name string
		f    func()
		site string
	}{
		{"a call of panic", explicitPanic, "panics.explicitPanic ("},
		{"a runtime error", nilDereference, "panics.nilDereference ("},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := catching(tc.f)
			if !strings.Contains(r.Site, tc.site) || !strings.Contains(r.Site, "panics_test.go:") {
				t.Errorf("Site = %q, want the frame of %s in panics_test.go", r.Site, tc.site)
			}
		})
	}
}

func TestCatchKeepsAPanicRaisedAgain(t *testing.T) {
	first := catching(explicitPanic)

	again := catching(func() { panic(first) })

	if again != first {
		t.Errorf("Catch of a re-raised panic = %+v at %s, want the first one at %s", again.Value, again.Site, first.Site)
	}
}

func TestCatchTellsOneHelperApartByItsCaller(t *testing.T) {
	direct := catching(explicitPanic)
	viaHelper := catching(callsExplicitPanic)
	again := catching(callsExplicitPanic)

	if direct.Site == viaHelper.Site {
		t.Errorf("Site of explicitPanic called from catching and from callsExplicitPanic = %q for both, want two sites", direct.Site)
	}
	if viaHelper.Site != again.Site {
		t.Errorf("Site of two panics through callsExplicitPanic = %q and %q, want one site", viaHelper.Site, again.Site)
	}
}

func TestRecoveredPrintsItsValueSiteAndStack(t *testing.T) {
	r := catching(explicitPanic)

	got := fmt.Sprint(r)

	for _, want := range []string{"boom at ", "panics.explicitPanic (", " [running]:"} {
		if !strings.Contains(got, want) {
			t.Errorf("fmt.Sprint of the caught panic = %q, want it to contain %q", got, want)
		}
	}
}
