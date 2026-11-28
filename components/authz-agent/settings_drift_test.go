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

package main

import (
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// knownSettingsDrift lists the settings drift the tests in this file find
// today, keyed by the case name they report. Each entry is a known defect:
// the test logs it instead of failing, and fails once the entry no longer
// matches anything, so that the change that fixes the defect also removes the
// entry.
var knownSettingsDrift = map[string]string{}

// reportSettingsDrift fails the test for every case in found that
// knownSettingsDrift does not list, and logs the listed ones. It also fails
// for every entry of knownSettingsDrift whose name starts with one of
// prefixes (the kinds of case the calling test reports) and that found does
// not contain.
func reportSettingsDrift(t *testing.T, found map[string]string, prefixes ...string) {
	t.Helper()
	for _, name := range slices.Sorted(maps.Keys(found)) {
		if defect, ok := knownSettingsDrift[name]; ok {
			t.Logf("known drift %q (%s): %s", name, defect, found[name])
			continue
		}
		t.Errorf("%s: %s", name, found[name])
	}
	for _, name := range slices.Sorted(maps.Keys(knownSettingsDrift)) {
		_, ok := found[name]
		if !ok && slices.ContainsFunc(prefixes, func(p string) bool { return strings.HasPrefix(name, p) }) {
			t.Errorf("%q no longer drifts; remove it from knownSettingsDrift", name)
		}
	}
}

// readEnvNames returns the variable of every key loadConfig reads.
func readEnvNames() map[string]bool {
	read := map[string]bool{}
	_, _ = loadConfig(func(key, fallback string) string {
		read[envName(key)] = true
		return fallback
	})
	return read
}

// withOne is loadConfig with the variable name set to value and every other
// key unset.
func withOne(name, value string) (config, error) {
	return loadConfig(func(key, fallback string) string {
		if envName(key) == name {
			return value
		}
		return fallback
	})
}

// readmeSetting is one variable of the configuration table in README.md:
// its default, "" where the row says empty, and the text of its Meaning
// column.
type readmeSetting struct {
	def, meaning string
}

// readmeRow matches a row of the configuration table whose first cell names
// one or more environment variables.
var readmeRow = regexp.MustCompile("(?m)^\\| (`[A-Z][A-Z0-9_]+`(?:, `[A-Z][A-Z0-9_]+`)*) \\| ([^|]*) \\| (.*) \\|$")

var backticked = regexp.MustCompile("`([^`]*)`")

// readmeSettings parses the configuration table of README.md. A row that
// names several variables gives their defaults in the same order.
func readmeSettings(t *testing.T) map[string]readmeSetting {
	t.Helper()
	raw, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatal(err)
	}
	settings := map[string]readmeSetting{}
	for _, row := range readmeRow.FindAllStringSubmatch(string(raw), -1) {
		names := backticked.FindAllStringSubmatch(row[1], -1)
		defs := backticked.FindAllStringSubmatch(row[2], -1)
		if strings.TrimSpace(row[2]) != "empty" && len(defs) != len(names) {
			t.Fatalf("README.md row %q gives %d defaults for %d variables", row[0], len(defs), len(names))
		}
		for i, name := range names {
			def := ""
			if strings.TrimSpace(row[2]) != "empty" {
				def = defs[i][1]
			}
			settings[name[1]] = readmeSetting{def: def, meaning: row[3]}
		}
	}
	if len(settings) == 0 {
		t.Fatalf("README.md has no row matching %s; the configuration table changed its format", readmeRow)
	}
	return settings
}

var chartEnvEntry = regexp.MustCompile(`(?m)^\s*- name: ([A-Z][A-Z0-9_]+)\s*$`)

// chartEnvNames returns the environment variables the chart sets on the
// container, under any condition of the template.
func chartEnvNames(t *testing.T) map[string]bool {
	t.Helper()
	const path = "../../helm-templates/authz-agent/templates/deployment.yaml"
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, m := range chartEnvEntry.FindAllStringSubmatch(string(raw), -1) {
		names[m[1]] = true
	}
	if len(names) == 0 {
		t.Fatalf("%s has no line matching %s; the env list changed its format", path, chartEnvEntry)
	}
	return names
}

// The variables loadConfig reads, the rows of the README configuration
// table, and the env entries of the chart name the same environment variables.
// A variable missing from the chart cannot be set by a Helm install.
func TestSettingsDrift_EveryVariableIsReadDocumentedAndRendered(t *testing.T) {
	read, doc, chart := readEnvNames(), readmeSettings(t), chartEnvNames(t)
	found := map[string]string{}
	for name := range read {
		if _, ok := doc[name]; !ok {
			found["no README row "+name] = "loadConfig reads it, and README.md has no row for it"
		}
		if !chart[name] {
			found["unrendered "+name] = "loadConfig reads it, and deployment.yaml sets no env entry for it"
		}
	}
	for name := range doc {
		if !read[name] {
			found["unread "+name] = "README.md documents it, and loadConfig never reads it"
		}
	}
	for name := range chart {
		if !read[name] {
			found["unread "+name] = "deployment.yaml sets it, and loadConfig never reads it"
		}
	}
	reportSettingsDrift(t, found, "no README row ", "unrendered ", "unread ")
}

// Setting a variable to the default its README row gives leaves the
// configuration as it is with nothing set.
func TestSettingsDrift_TheDocumentedDefaultIsTheDefault(t *testing.T) {
	want := mustLoad(t, nil)
	for name, s := range readmeSettings(t) {
		got, err := withOne(name, s.def)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Errorf("loadConfig with %s=%q = %+v, %v; want the configuration with nothing set, %+v", name, s.def, got, err, want)
		}
	}
}

// emptyMeaning matches a Meaning cell that states what the empty value
// does, in a clause that opens with "empty": "empty disables the pull".
// "It may not be empty" states no meaning.
var emptyMeaning = regexp.MustCompile(`(?i)(^|[;.] )empty\b`)

// A boundary value that loadConfig accepts, so that the configuration
// differs from the one with nothing set, has a meaning only where the
// README row names it: a clause opening with "empty" for "", `0` for 0. A
// value loadConfig refuses has none to document.
func TestSettingsDrift_EveryAcceptedBoundaryValueIsDocumented(t *testing.T) {
	doc := readmeSettings(t)
	unset := mustLoad(t, nil)
	found := map[string]string{}
	for name := range readEnvNames() {
		row, ok := doc[name]
		if !ok {
			continue // reported by TestSettingsDrift_EveryVariableIsReadDocumentedAndRendered
		}
		probes := map[string]bool{"": emptyMeaning.MatchString(row.meaning)}
		if _, err := strconv.Atoi(row.def); err == nil {
			probes["0"] = strings.Contains(row.meaning, "`0`")
		}
		for value, named := range probes {
			got, err := withOne(name, value)
			if named || err != nil || reflect.DeepEqual(got, unset) {
				continue
			}
			found["undocumented "+name+"="+printable(value)] = "loadConfig accepts it, and the README row does not say what it means"
		}
	}
	reportSettingsDrift(t, found, "undocumented ")
}

// printable spells value the way the case names in knownSettingsDrift do.
func printable(value string) string {
	if value == "" {
		return `""`
	}
	return value
}

// Every variable loadConfig reads goes through one rule: a value it does
// not accept fails the start with an error that quotes the variable and the
// value, and names no other variable. The probes are values one of the
// kinds of setting refuses.
func TestSettingsDrift_EveryRefusalNamesItsVariable(t *testing.T) {
	read := readEnvNames()
	for name := range read {
		for _, value := range []string{"", "0", "-1", "soon", "1.5"} {
			_, err := withOne(name, value)
			if err == nil {
				continue
			}
			if want := name + " is " + strconv.Quote(value) + "; expected "; !strings.Contains(err.Error(), want) {
				t.Errorf("loadConfig with %s=%q: error %q, want one containing %q", name, value, err, want)
			}
			for other := range read {
				if other != name && strings.Contains(err.Error(), other+" ") {
					t.Errorf("loadConfig with %s=%q: error %q also names %s, which is unset", name, value, err, other)
				}
			}
		}
	}
}

const chartDir = "../../helm-templates/authz-agent"

var (
	valuesKey     = regexp.MustCompile(`(?m)^(AUTHZ_[A-Z0-9_]+):`)
	authzName     = regexp.MustCompile(`\bAUTHZ_[A-Z0-9_]+\b`)
	valuesUsedKey = regexp.MustCompile(`\.Values\.(AUTHZ_[A-Z0-9_]+)\b`)
)

// readFile returns the text of path, failing the test when it cannot.
func readFile(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// The settings values.yaml offers reach the container: every variable of
// the agent that values.yaml names is an env entry of the chart, every
// AUTHZ_ key that values.yaml declares is declared in values.schema.json
// and read by a template, and every AUTHZ_ key a template reads is
// declared in values.yaml, so that no env entry renders empty.
func TestSettingsDrift_EveryValueTheChartOffersReachesTheContainer(t *testing.T) {
	values := readFile(t, chartDir+"/values.yaml")
	var schema struct {
		Properties map[string]json.RawMessage `json:"properties"`
	}
	if err := json.Unmarshal([]byte(readFile(t, chartDir+"/values.schema.json")), &schema); err != nil {
		t.Fatal(err)
	}
	paths, err := filepath.Glob(chartDir + "/templates/*")
	if err != nil || len(paths) == 0 {
		t.Fatalf("templates of %s: %v, %d files", chartDir, err, len(paths))
	}
	used := map[string]bool{}
	for _, path := range paths {
		for _, m := range valuesUsedKey.FindAllStringSubmatch(readFile(t, path), -1) {
			used[m[1]] = true
		}
	}
	declared := map[string]bool{}
	for _, m := range valuesKey.FindAllStringSubmatch(values, -1) {
		declared[m[1]] = true
	}
	read, chart := readEnvNames(), chartEnvNames(t)
	found := map[string]string{}
	for _, name := range authzName.FindAllString(values, -1) {
		if read[name] && !chart[name] {
			found["unrendered "+name] = "values.yaml names it, and deployment.yaml sets no env entry for it"
		}
	}
	for name := range declared {
		if _, ok := schema.Properties[name]; !ok {
			found["unschematized "+name] = "values.yaml declares it, and values.schema.json has no property for it"
		}
		if !used[name] {
			found["unused "+name] = "values.yaml declares it, and no template reads it"
		}
	}
	for name := range used {
		if !declared[name] {
			found["undeclared "+name] = "a template reads it, and values.yaml declares no default for it"
		}
	}
	reportSettingsDrift(t, found, "unschematized ", "unused ", "undeclared ")
}

// The startup error README.md quotes is the one loadConfig returns for the
// value it quotes.
func TestSettingsDrift_TheQuotedStartupErrorIsTheOneReturned(t *testing.T) {
	raw, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile("(?m)^```text\n(invalid configuration: (AUTHZ_[A-Z0-9_]+) is \"([^\"]*)\";.*)\n```$").FindSubmatch(raw)
	if m == nil {
		t.Fatal("README.md has no text block quoting an invalid configuration error")
	}
	_, got := withOne(string(m[2]), string(m[3]))
	if got == nil || got.Error() != string(m[1]) {
		t.Errorf("loadConfig with %s=%q: error %v, want the README text %q", m[2], m[3], got, m[1])
	}
}
