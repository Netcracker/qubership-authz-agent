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

import (
	"strings"
	"testing"
)

// runSetup runs setup as the subtest "setup" of t and returns the report of its
// failure, or "" when it succeeded. A failure fails that subtest, with a message
// that starts with setupBrokenPrefix; a setup that stops its subtest with
// t.Fatal is reported the same way. When -run leaves the subtest out, setup does
// not run and the report says so: the checks after it wait on a stand nobody
// set up.
func runSetup(t *testing.T, setup func(t *testing.T) error) string {
	t.Helper()
	return runNamedSetup(t, "setup", setup)
}

// runNamedSetup is runSetup with a subtest named name.
func runNamedSetup(t *testing.T, name string, setup func(t *testing.T) error) string {
	t.Helper()
	broken := ""
	ran := false
	ok := t.Run(name, func(t *testing.T) {
		ran = true
		if err := setup(t); err != nil {
			broken = setupBroken(err)
			t.Error(broken)
		}
	})
	if !ran {
		// Running setup in t instead would let its t.Fatal stop t before the
		// checks are skipped and counted.
		match := strings.ReplaceAll(name, " ", "_")
		broken = setupBrokenPrefix + ": -run or -skip left out the subtest " + match +
			" this check waits on; select it too"
		t.Error(broken)
		return broken
	}
	if !ok && broken == "" {
		broken = setupBrokenPrefix + ": the " + name + " subtest failed, see its output"
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
