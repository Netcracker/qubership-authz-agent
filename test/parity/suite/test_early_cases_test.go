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

// The early cases were the first the suite asked: operator forms, condition
// forms, and regular policy sets. Most of them are data under
// testdata/cases/early, written by generate.py there, which says what each file
// asks. They were first written in Go, and each file sends the requests the Go
// cases sent, so the goldens recorded then still apply. Each function runs its
// own file, so that a recording run can be filtered to it and record it on a
// stand of its own.

// TestIsolatedPolicyCases runs early/isolated-policy.json.
func (s *ParitySuite) TestIsolatedPolicyCases() { s.runCaseFile("early/isolated-policy.json") }

// TestIsolatedConditionFormCases runs early/isolated-condition-form.json.
func (s *ParitySuite) TestIsolatedConditionFormCases() {
	s.runCaseFile("early/isolated-condition-form.json")
}

// TestRegularPolicySetCases runs early/regular-policy-set.json and then
// regularPolicySetCases: three cases a case file cannot express, and
// inactive-set, which runs between them in the recorded order. On the
// authz-agent profile, which loads simplified policies only, the first runner
// skips the rest of the function. The file's cases read no PIP, so the cleanup
// of the second runner, which empties the isolated domain before the first
// runner empties the file's sets, leaves no set naming a missing declaration.
func (s *ParitySuite) TestRegularPolicySetCases() {
	s.runCaseFile("early/regular-policy-set.json")
	s.runRegularCases(regularPolicySetCases())
}
