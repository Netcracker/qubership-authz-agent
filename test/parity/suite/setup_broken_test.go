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

//go:build integration

package paritysuite

import "testing"

// runSetup runs setup as the subtest "setup" of t and returns the report of its
// failure, or "" when it succeeded. A failure fails that subtest alone, with a
// message that starts with setupBrokenPrefix; a setup that stops its subtest
// with t.Fatal is reported the same way.
func runSetup(t *testing.T, setup func(t *testing.T) error) string {
	t.Helper()
	broken := ""
	ok := t.Run("setup", func(t *testing.T) {
		if err := setup(t); err != nil {
			broken = setupBroken(err)
			t.Error(broken)
		}
	})
	if !ok && broken == "" {
		broken = setupBrokenPrefix + ": the setup subtest failed, see its output"
	}
	return broken
}

// skipIfBroken skips t, a check that waited on a setup, when that setup broke.
// The reason starts with setupBrokenPrefix.
func skipIfBroken(t *testing.T, broken string) {
	t.Helper()
	if broken != "" {
		t.Skipf("%s; not compared", broken)
	}
}
