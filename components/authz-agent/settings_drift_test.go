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
	"maps"
	"os"
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
var knownSettingsDrift = map[string]string{
	"unrendered AUTHZ_PIP_TIMEOUT": "F57: the chart renders no AUTHZ_PIP_TIMEOUT, " +
		"so a Helm install cannot raise the 2 s limit on a PIP call",
	"unrendered AUTHZ_DEFAULT_TENANT": "N-E1: the chart renders no AUTHZ_DEFAULT_TENANT, " +
		"so a Helm install cannot choose the tenant of a request that names none",
	"undocumented AUTHZ_PIP_TIMEOUT=0": "F54: a PIP timeout of 0 is accepted and means the 2 s default, " +
		"which the README row does not say",
	`undocumented AUTHZ_DEFAULT_TENANT=""`: "F55: an empty default tenant is accepted, /ready answers 200, " +
		"and every request that names no tenant is denied; the README row does not say so",
	"undocumented AUTHZ_JWKS_HTTP_TIMEOUT=0": "N-E2: a JWKS timeout of 0 is accepted and means the 5 s default, " +
		"which the README row does not say",
	"undocumented AUTHZ_M2M_RENEW_BEFORE_SECONDS=0": "N-E3: 0 is accepted and refreshes the M2M token " +
		"only at its expiry, which the README row does not say",
	`undocumented AUTHZ_HTTP_ADDR=""`: "N-E4: an empty listen address is accepted and listens on " +
		"a random port, which the README row does not say",
	`undocumented AUTHZ_PUBLIC_ADDR=""`: "N-E4: an empty listen address is accepted and listens on " +
		"a random port, which the README row does not say",
	`undocumented AUTHZ_M2M_CLIENT_ID_FILE=""`: "N-E5: an empty file name is accepted, " +
		"and the README row does not say what it means",
	`undocumented AUTHZ_M2M_CLIENT_SECRET_FILE=""`: "N-E5: an empty file name is accepted, " +
		"and the README row does not say what it means",
	`undocumented AUTHZ_PAP_CLIENT_TOKEN_FILE=""`: "N-E5: an empty file name is accepted, " +
		"and the README row does not say what it means",
}

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

// envName is the environment variable configloader reads for a key:
// authz.http.addr is AUTHZ_HTTP_ADDR.
func envName(key string) string {
	return strings.ToUpper(strings.ReplaceAll(key, ".", "_"))
}

// readEnvNames returns the variable of every key loadConfig reads.
func readEnvNames() map[string]bool {
	read := map[string]bool{}
	loadConfig(func(key, fallback string) string {
		read[envName(key)] = true
		return fallback
	})
	return read
}

// withOne is loadConfig with the variable name set to value and every other
// key unset.
func withOne(name, value string) config {
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
// one or more AUTHZ_ variables.
var readmeRow = regexp.MustCompile("(?m)^\\| (`AUTHZ_[A-Z0-9_]+`(?:, `AUTHZ_[A-Z0-9_]+`)*) \\| ([^|]*) \\| (.*) \\|$")

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

var chartEnvEntry = regexp.MustCompile(`(?m)^\s*- name: (AUTHZ_[A-Z0-9_]+)\s*$`)

// chartEnvNames returns the AUTHZ_ variables the chart sets on the container,
// under any condition of the template.
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
// table, and the env entries of the chart name the same AUTHZ_ variables.
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
	want := loadConfig(fromMap(nil))
	for name, s := range readmeSettings(t) {
		if got := withOne(name, s.def); !reflect.DeepEqual(got, want) {
			t.Errorf("loadConfig with %s=%q = %+v, want the configuration with nothing set, %+v", name, s.def, got, want)
		}
	}
}

// A boundary value that loadConfig accepts, so that the configuration
// differs from the one with nothing set, has a meaning only where the
// README row names it: "empty" for "", `0` for 0. A value loadConfig
// replaces by the default has none to document.
func TestSettingsDrift_EveryAcceptedBoundaryValueIsDocumented(t *testing.T) {
	doc := readmeSettings(t)
	unset := loadConfig(fromMap(nil))
	found := map[string]string{}
	for name := range readEnvNames() {
		row, ok := doc[name]
		if !ok {
			continue // reported by TestSettingsDrift_EveryVariableIsReadDocumentedAndRendered
		}
		probes := map[string]bool{"": strings.Contains(strings.ToLower(row.meaning), "empty")}
		if _, err := strconv.Atoi(row.def); err == nil {
			probes["0"] = strings.Contains(row.meaning, "`0`")
		}
		for value, named := range probes {
			if named || reflect.DeepEqual(withOne(name, value), unset) {
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
