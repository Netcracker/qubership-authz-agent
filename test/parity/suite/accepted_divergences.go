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

package paritysuite

import (
	"fmt"
	"path/filepath"
	"strings"
)

// acceptedDivergenceRoot holds one file per accepted divergence, at
// <golden key>.json. It is deliberately a separate tree: the golden
// directory is immutable evidence recorded from live access-control, and mixing
// "what the agent does instead" into it would blur that line.
const acceptedDivergenceRoot = "testdata/accepted-divergences"

// AcceptedDivergence records a case where authz-agent knowingly answers
// differently from the legacy golden.
//
// This is NOT a way to silence a failing case. The case still runs, still calls
// the agent, and its response is still compared byte-for-byte — only against the
// recorded divergent answer instead of the golden. Three outcomes follow:
//
//   - the agent matches the golden        -> pass (the divergence is gone; the
//     entry here is now stale and should be deleted)
//   - the agent matches this record       -> pass, with a line in the test log
//   - the agent matches neither           -> fail
//
// So a regression that changes the answer a third way is still caught, which is
// the property a t.Skip would have thrown away.
type AcceptedDivergence struct {
	// Reason states why the agent is allowed to differ, in one sentence.
	Reason string
	// Decision names where the decision is written down in full.
	Decision string
}

// acceptedDivergences is keyed by "<row id>|<subCase>".
//
// Every entry needs a decision document. Adding one without it, or adding one to
// make an unexplained failure go away, defeats the purpose of the suite.
var acceptedDivergences = map[string]AcceptedDivergence{
	key(PSUITE_ROW_2_CHECK_RESOURCE_V1, "general-pip-dict/allow"): {
		Reason: "The agent resolves the dict aliases returned by a GENERAL PIP, which " +
			"legacy access-control could not, so it allows where legacy denied by inability " +
			"rather than by policy.",
		Decision: "docs/parity/general-pip-dict-divergences.md",
	},
	key(PSUITE_ROW_3_CHECK_RESOURCE_BULK_V1, "general-pip-dict"): {
		Reason: "Same dict-alias resolution as row 2, seen through the bulk endpoint: the " +
			"agent returns the ids legacy left out because it could not evaluate the condition.",
		Decision: "docs/parity/general-pip-dict-divergences.md",
	},
	key(PSUITE_ROW_7_CHECK_RESOURCE_V2, "general-pip-dict/allow"): {
		Reason:   "Same dict-alias resolution as row 2, on the v2 response shape.",
		Decision: "docs/parity/general-pip-dict-divergences.md",
	},
}

// acceptedExportDivergences is keyed by the difference class the
// specification's export bundle gives a golden of the export-fed profile
// (TestExportFedAgent): set-type, conversion, tenant, pip-kind. A golden after
// an export the agent did not load, which the bundle gives the class
// pull-failure, is not compared (verdictBroken).
// A class is accepted, not a case, because one decision about the conversion
// explains every golden of the class. Such a golden still runs and passes only
// when the agent answers exactly as the bundle predicts for it, so an agent that
// answers a third way still fails.
//
// Every entry needs a decision document, as acceptedDivergences does. An
// answer that allows what the golden denies (grantsMore) is never accepted:
// it is an agent defect unless the rule it rests on is one an entry's
// decision covers, and no check of the profile can tell from a golden which
// rule an allow rests on. The legacy-export check (TestExportFedLegacyAgent)
// also keys this map by the classes it derives from the exports legacy held
// (legacyClass), such as undeclared-pip, which the bundle never gives.
var acceptedExportDivergences = map[string]AcceptedDivergence{
	"set-type": {
		Reason: "The agent evaluates the simplified model only: it skips every policy set whose type is not " +
			"SIMPLIFIED, so a decision that rests on a regular policy set differs from legacy.",
		Decision: "docs/parity/export-fed-agent-divergences.md",
	},
	// TestExportFedOwnerDecisions reads this entry too, as the answer it
	// wants for a decision legacy refused because of such an attribute.
	"undeclared-pip": {
		Reason: "A subject attribute with no declared PIP counts as a PIP that failed: the comparison " +
			"that reads it has an unknown value, the agent evaluates the rest of the condition, answers 200, " +
			"allows a request only where the answer does not depend on that value, and names the set in " +
			"/health; legacy answers 400 to every check of the tenant while one of its sets reads such an attribute.",
		Decision: "docs/parity/export-fed-agent-divergences.md",
	},
}

func key(id ParityEndpointID, subCase string) string {
	return fmt.Sprintf("%d|%s", int(id), subCase)
}

// acceptedDivergenceFor returns the record for a case, if one exists.
func acceptedDivergenceFor(id ParityEndpointID, subCase string) (AcceptedDivergence, bool) {
	d, ok := acceptedDivergences[key(id, subCase)]
	return d, ok
}

// acceptedDivergencePath returns the file of the accepted answer of the golden
// key: <acceptedDivergenceRoot>/<key>.json.
func acceptedDivergencePath(key string) string {
	return filepath.Join(acceptedDivergenceRoot, filepath.FromSlash(key)+".json")
}

// AcceptedDivergenceDriftError is returned when a case is registered as an
// accepted divergence but the agent now answers a third way — neither the golden
// nor the recorded divergence. That is a real finding: the behaviour moved after
// someone decided it was settled.
type AcceptedDivergenceDriftError struct {
	GoldenPath   string
	AcceptedPath string
	Reason       string
	Diff         string
}

func (e *AcceptedDivergenceDriftError) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "accepted divergence drifted at %s\n", e.AcceptedPath)
	fmt.Fprintf(&b, "  the case diverges from the golden %s, which is expected: %s\n", e.GoldenPath, e.Reason)
	fmt.Fprintf(&b, "  but it no longer matches the recorded divergence either:\n%s", e.Diff)
	fmt.Fprintf(&b, "  Decide which is right before touching the recorded file: the agent may have\n")
	fmt.Fprintf(&b, "  regressed, or the divergence may have widened.\n")
	return b.String()
}
