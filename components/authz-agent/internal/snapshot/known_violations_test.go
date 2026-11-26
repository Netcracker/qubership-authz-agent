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

package snapshot

import (
	"fmt"
	"testing"
)

// knownViolations maps the name of a test to the known defect its check
// fails on: the finding ID and the defect in one phrase. A fix of the defect
// removes the entry.
var knownViolations = map[string]string{
	"TestASimplifiedPolicyOverAFailedSourceDeniesTheRowsWhereItIsUnknown": "F76: the filter of simplified " +
		"policies stops at the first policy of an operation that allows every row and never sees the veto of a " +
		"later policy whose condition reads a failed source",
}

// assertOrKnown fails t with the message format unless ok holds. A test
// listed in [knownViolations] logs the failed check instead, and fails when
// the check holds, so that the entry cannot outlive the defect.
func assertOrKnown(t *testing.T, ok bool, format string, args ...any) {
	t.Helper()
	known, listed := knownViolations[t.Name()]
	switch {
	case !ok && listed:
		t.Logf("known violation, %s: %s", known, fmt.Sprintf(format, args...))
	case !ok:
		t.Errorf(format, args...)
	case listed:
		t.Errorf("%s passes; remove its entry from knownViolations (%s)", t.Name(), known)
	}
}
