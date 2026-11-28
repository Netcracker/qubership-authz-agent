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

package gorules_test

import (
	"testing"

	"github.com/quasilyte/go-ruleguard/analyzer"
	"golang.org/x/tools/go/analysis/analysistest"
)

// The packages under testdata mark each line a rule must report with a want
// comment and leave unmarked the lines it must not: analysistest fails on a
// report missing from either side. The module there is named authz-agent, as
// the repository is, so the rules that name its packages apply to it.
func TestRulesReportWhatTestdataMarks(t *testing.T) {
	if err := analyzer.Analyzer.Flags.Set("rules", "rules.go"); err != nil {
		t.Fatal(err)
	}
	analysistest.Run(t, analysistest.TestData(), analyzer.Analyzer, "./...")
}
