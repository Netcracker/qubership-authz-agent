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

package pips

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestLoadEntitlementsConfigFromEnv(t *testing.T) {
	cases := []struct {
		name     string
		env      map[string]string
		expected *EntitlementsConfig
	}{
		{
			name:     "unset URL returns nil",
			env:      nil,
			expected: nil,
		},
		{
			name:     "blank URL returns nil",
			env:      map[string]string{EnvEntitlementsURL: "   "},
			expected: nil,
		},
		{
			name:     "URL with no trailing slash is preserved as-is",
			env:      map[string]string{EnvEntitlementsURL: "http://entitlements-mock:8080"},
			expected: &EntitlementsConfig{URL: "http://entitlements-mock:8080", HTTPTimeoutSeconds: DefaultEntitlementsHTTPTimeout, HTTPRetries: DefaultEntitlementsHTTPRetries},
		},
		{
			name:     "trailing slash stripped",
			env:      map[string]string{EnvEntitlementsURL: "http://entitlements-mock:8080/"},
			expected: &EntitlementsConfig{URL: "http://entitlements-mock:8080", HTTPTimeoutSeconds: DefaultEntitlementsHTTPTimeout, HTTPRetries: DefaultEntitlementsHTTPRetries},
		},
		{
			name: "explicit knobs applied",
			env: map[string]string{
				EnvEntitlementsURL:         "http://entitlements-mock:8080",
				EnvEntitlementsHTTPTimeout: "2",
				EnvEntitlementsHTTPRetries: "10",
			},
			expected: &EntitlementsConfig{URL: "http://entitlements-mock:8080", HTTPTimeoutSeconds: 2, HTTPRetries: 10},
		},
		{
			name: "unparseable knobs fall back to defaults",
			env: map[string]string{
				EnvEntitlementsURL:         "http://entitlements-mock:8080",
				EnvEntitlementsHTTPTimeout: "oops",
				EnvEntitlementsHTTPRetries: "-4",
			},
			expected: &EntitlementsConfig{URL: "http://entitlements-mock:8080", HTTPTimeoutSeconds: DefaultEntitlementsHTTPTimeout, HTTPRetries: DefaultEntitlementsHTTPRetries},
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			for _, key := range []string{EnvEntitlementsURL, EnvEntitlementsHTTPTimeout, EnvEntitlementsHTTPRetries} {
				t.Setenv(key, "")
			}
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			got := LoadEntitlementsConfigFromEnv()
			if !reflect.DeepEqual(got, tc.expected) {
				t.Fatalf("LoadEntitlementsConfigFromEnv() = %+v, want %+v", got, tc.expected)
			}
		})
	}
}

func TestApplyEntitlementsOverride_AddsAndRemoves(t *testing.T) {
	doc := EmptyDocumentWithEntitlements(nil)
	if doc.Normalized.Remote.Entitlements != nil {
		t.Fatalf("nil cfg should produce no remote.entitlements entry")
	}
	if _, ok := doc.Normalized.ByName[EntitlementsPIPName]; ok {
		t.Fatalf("nil cfg should produce no byName entry for %s", EntitlementsPIPName)
	}

	cfg := &EntitlementsConfig{URL: "http://entitlements-mock:8080", HTTPTimeoutSeconds: 7, HTTPRetries: 2}
	ApplyEntitlementsOverride(doc, cfg)
	if doc.Normalized.Remote.Entitlements == nil {
		t.Fatalf("expected remote.entitlements populated after override")
	}
	entry := doc.Normalized.Remote.Entitlements
	if entry.URL != cfg.URL || entry.HTTPTimeoutSeconds != cfg.HTTPTimeoutSeconds || entry.HTTPRetries != cfg.HTTPRetries {
		t.Fatalf("entry mismatch: got %+v want url=%s timeout=%d retries=%d", entry, cfg.URL, cfg.HTTPTimeoutSeconds, cfg.HTTPRetries)
	}
	if got := doc.Normalized.ByName[EntitlementsPIPName]; got.PipType != PipTypeEntitlements || got.Alias != EntitlementsPIPAlias {
		t.Fatalf("byName entry mismatch: %+v", got)
	}
	if !doc.Normalized.AliasSet[EntitlementsPIPAlias] {
		t.Fatalf("aliasSet should carry entitledResources alias")
	}

	// Applying nil cfg should remove the container-pinned entry.
	ApplyEntitlementsOverride(doc, nil)
	if doc.Normalized.Remote.Entitlements != nil {
		t.Fatalf("nil cfg should remove remote.entitlements")
	}
	if _, ok := doc.Normalized.ByName[EntitlementsPIPName]; ok {
		t.Fatalf("nil cfg should remove byName entry")
	}
	if doc.Normalized.AliasSet[EntitlementsPIPAlias] {
		t.Fatalf("nil cfg should remove aliasSet entry")
	}

	// Re-applying the same cfg should be idempotent.
	ApplyEntitlementsOverride(doc, cfg)
	ApplyEntitlementsOverride(doc, cfg)
	if doc.Normalized.Remote.Entitlements.URL != cfg.URL {
		t.Fatalf("idempotent re-apply failed")
	}
}

func TestApplyEntitlementsOverride_PreservesUserUploads(t *testing.T) {
	items := []SimplifiedPIP{{
		Name:              "subject.parityDepartment",
		PipType:           PipTypeGeneral,
		URL:               "http://pip-mock:8090/api/v1/pip/dept",
		HTTPMethod:        "GET",
		RequestAttributes: map[string]string{"resourceType": "PARITY_SUITE_ROW_02"},
	}}
	doc, _, err := NormalizeItems(items)
	if err != nil {
		t.Fatalf("NormalizeItems: %v", err)
	}
	cfg := &EntitlementsConfig{URL: "http://entitlements-mock:8080", HTTPTimeoutSeconds: 5, HTTPRetries: 3}
	ApplyEntitlementsOverride(doc, cfg)

	if _, ok := doc.Normalized.Remote.General["subject.parityDepartment"]; !ok {
		t.Fatalf("expected uploaded GENERAL PIP to survive override merge")
	}
	if doc.Normalized.Remote.Entitlements == nil {
		t.Fatalf("expected entitlements entry after override")
	}
	if doc.Normalized.ByName["subject.parityDepartment"].PipType != PipTypeGeneral {
		t.Fatalf("uploaded PIP byName entry should stay intact")
	}
	if doc.Normalized.ByName[EntitlementsPIPName].PipType != PipTypeEntitlements {
		t.Fatalf("entitlements byName entry missing after override")
	}

	// Round-trip through JSON so we confirm the OPA-bound payload shape
	// is serialisable and the entitlements entry survives marshalling.
	raw, err := json.Marshal(&doc.Normalized)
	if err != nil {
		t.Fatalf("marshal normalized: %v", err)
	}
	var decoded NormalizedPIPs
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("unmarshal normalized: %v", err)
	}
	if decoded.Remote.Entitlements == nil || decoded.Remote.Entitlements.URL != cfg.URL {
		t.Fatalf("entitlements entry did not round-trip through JSON: %+v", decoded.Remote.Entitlements)
	}
}

func TestValidate_RejectsEntitlementUpload(t *testing.T) {
	// D-AG-16 message contract: the rejection names the env var so an
	// operator reading the HTTP 400 body learns the runtime knob.
	item := SimplifiedPIP{
		Name:    "subject.entitledResources",
		PipType: PipTypeEntitlements,
		URL:     "http://whoever:8080",
	}
	err := Validate([]SimplifiedPIP{item})
	if err == nil {
		t.Fatalf("expected Validate to reject ENTITLEMENT upload")
	}
	msg := err.Error()
	if !strings.Contains(msg, `pipType "ENTITLEMENT"`) {
		t.Fatalf("expected message to mention pipType ENTITLEMENT, got %q", msg)
	}
	if !strings.Contains(msg, "AUTHZ_ENTITLEMENTS_URL") {
		t.Fatalf("expected message to mention AUTHZ_ENTITLEMENTS_URL env var, got %q", msg)
	}
	if !strings.Contains(msg, "container-pinned") {
		t.Fatalf("expected message to mention container-pinned, got %q", msg)
	}
}

func TestEmptyDocumentWithEntitlements_RoundTrip(t *testing.T) {
	cfg := &EntitlementsConfig{URL: "http://entitlements-mock:8080", HTTPTimeoutSeconds: 2, HTTPRetries: 1}
	doc := EmptyDocumentWithEntitlements(cfg)
	raw, err := MarshalDocument(doc)
	if err != nil {
		t.Fatalf("MarshalDocument: %v", err)
	}
	var decoded PIPDocument
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded.Normalized.Remote.Entitlements == nil {
		t.Fatalf("round-trip dropped entitlements entry")
	}
	if got := decoded.Normalized.Remote.Entitlements.URL; got != cfg.URL {
		t.Fatalf("round-trip URL mismatch: got %q want %q", got, cfg.URL)
	}
}
