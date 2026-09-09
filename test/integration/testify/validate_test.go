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

package runtimetest

import (
	"os"
	"strings"
	"testing"
)

// TestCatalogNoDuplicates verifies that the catalog has no duplicate step names.
// This is a structural test — no live stack is required.
func TestCatalogNoDuplicates(t *testing.T) {
	seen := make(map[string]bool, len(Catalog))
	for _, e := range Catalog {
		if seen[e.Name] {
			t.Errorf("duplicate step name in catalog: %s", e.Name)
		}
		seen[e.Name] = true
	}
}

// TestCatalogMatchesReadme verifies bidirectional parity between the catalog
// and the committed step table in test/readme.md.
func TestCatalogMatchesReadme(t *testing.T) {
	content, err := os.ReadFile("../../readme.md")
	if err != nil {
		t.Fatalf("cannot read test/readme.md: %v", err)
	}

	tableEntries := parseStepTable(string(content))
	if len(tableEntries) == 0 {
		t.Fatal("no step entries found in test/readme.md table")
	}

	readmeSeen := make(map[string]bool, len(tableEntries))
	for _, e := range tableEntries {
		if readmeSeen[e.Name] {
			t.Errorf("duplicate step name in readme table: %s", e.Name)
		}
		readmeSeen[e.Name] = true
	}

	readmeByName := make(map[string]StepEntry, len(tableEntries))
	for _, e := range tableEntries {
		readmeByName[e.Name] = e
	}

	for _, ce := range Catalog {
		re, ok := readmeByName[ce.Name]
		if !ok {
			t.Errorf("catalog step %q is missing from readme table", ce.Name)
			continue
		}
		if re.Username != ce.Username {
			t.Errorf("step %q username mismatch: catalog=%q readme=%q", ce.Name, ce.Username, re.Username)
		}
		if re.Endpoint != ce.Endpoint {
			t.Errorf("step %q endpoint mismatch: catalog=%q readme=%q", ce.Name, ce.Endpoint, re.Endpoint)
		}
		if re.Resource != ce.Resource {
			t.Errorf("step %q resource mismatch: catalog=%q readme=%q", ce.Name, ce.Resource, re.Resource)
		}
		if re.Operation != ce.Operation {
			t.Errorf("step %q operation mismatch: catalog=%q readme=%q", ce.Name, ce.Operation, re.Operation)
		}
		if re.TokenRoles != ce.TokenRoles {
			t.Errorf("step %q token_roles mismatch: catalog=%q readme=%q", ce.Name, ce.TokenRoles, re.TokenRoles)
		}
	}

	for _, re := range tableEntries {
		if _, ok := CatalogByName[re.Name]; !ok {
			t.Errorf("readme step %q is not registered in the catalog", re.Name)
		}
	}
}

// parseStepTable extracts StepEntry rows from the "## Runtime Integration Test Steps" table.
// Expected columns: Step Name | Username | Endpoint | Resource | Operation | Token Roles
func parseStepTable(content string) []StepEntry {
	lines := strings.Split(content, "\n")
	var inTable bool
	var headerDone bool
	var entries []StepEntry

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		if !inTable {
			if strings.Contains(trimmed, "Step Name") && strings.Contains(trimmed, "Endpoint") && strings.HasPrefix(trimmed, "|") {
				inTable = true
				continue
			}
			continue
		}

		if !headerDone {
			if strings.Contains(trimmed, "---") {
				headerDone = true
			}
			continue
		}

		if !strings.HasPrefix(trimmed, "|") {
			break
		}

		parts := strings.Split(trimmed, "|")
		if len(parts) < 7 {
			continue
		}

		name := strings.TrimSpace(parts[1])
		if name == "" {
			continue
		}

		entries = append(entries, StepEntry{
			Name:       strings.Trim(name, "`"),
			Username:   strings.TrimSpace(parts[2]),
			Endpoint:   strings.Trim(strings.TrimSpace(parts[3]), "`"),
			Resource:   strings.TrimSpace(parts[4]),
			Operation:  strings.TrimSpace(parts[5]),
			TokenRoles: strings.TrimSpace(parts[6]),
		})
	}
	return entries
}
