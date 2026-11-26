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
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// bodyServer answers every call with ["x"] and records the body of the
// latest call.
func bodyServer(t *testing.T) (*httptest.Server, func() string) {
	t.Helper()
	var mu sync.Mutex
	var last string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		last = string(b)
		mu.Unlock()
		_, _ = w.Write([]byte(`["x"]`))
	}))
	t.Cleanup(srv.Close)
	return srv, func() string {
		mu.Lock()
		defer mu.Unlock()
		return last
	}
}

// callBody loads each of pips in turn into one registry, with a set whose
// condition reads subject.g, decides one request, and returns the body the
// PIP received.
func callBody(t *testing.T, pips ...string) string {
	t.Helper()
	srv, lastBody := bodyServer(t)
	r := pipRegistry(t)
	for _, p := range pips {
		policySets, pipsDoc := documents(fmt.Sprintf(p, srv.URL), set("a", "subject.g == 'x'"))
		if _, err := r.Load(context.Background(), policySets, pipsDoc); err != nil {
			t.Fatalf("Load of %s: %v", p, err)
		}
	}
	decide(t, r, readDoc(t, "a", "y", 1))
	return lastBody()
}

// A reload whose only change turns a PIP's absent requestAttributes into {}
// calls the PIP as a fresh load of the new declaration does. The two
// declarations dump to the same text and generate the same Rego.
func TestAReloadFromAbsentToEmptyRequestAttributesCallsAsAFreshLoad(t *testing.T) {
	const (
		absent = `{"tenantId": "a", "name": "subject.g", "pipType": "GENERAL", "url": %q, "httpMethod": "POST"}`
		empty  = `{"tenantId": "a", "name": "subject.g", "pipType": "GENERAL", "url": %q, "httpMethod": "POST",
			"requestAttributes": {}}`
	)
	fresh := callBody(t, empty)
	if old := callBody(t, absent); old == fresh {
		t.Fatalf("body of the call with requestAttributes absent = %q, the same as with {}", old)
	}

	if got := callBody(t, absent, empty); got != fresh {
		t.Errorf("body of the call after a reload from absent requestAttributes to {} = %q, want %q as after a fresh load",
			got, fresh)
	}
}

// A load that changes another tenant leaves a tenant whose export is refused
// as it was: the refusal is neither counted again nor replaced.
func TestAnUnchangedExportRefusalIsNotCountedAgain(t *testing.T) {
	notGlobal := `{"type": "SIMPLIFIED", "tenantId": "a", "component": "C", "status": "ACTIVE",
		"combiningAlgorithm": "DENY_UNLESS_PERMIT", "policySetId": "s-all", "target": "true",
		"policies": [{"combiningAlgorithm": "DENY_UNLESS_PERMIT", "target": "true", "tenantId": "a",
			"rules": [{"ruleId": "r-all", "effect": "ALLOW", "target": "subject.roles CONTAINS ANY 'A'",
				"tenantId": "a"}]}]}`
	r := New(Config{}, tab(t), quiet{})
	loadSets := func(sets ...string) LoadSummary {
		t.Helper()
		policySets, pipsDoc := documents(``, sets...)
		sum, err := r.Load(context.Background(), policySets, pipsDoc)
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		return sum
	}
	if sum := loadSets(notGlobal, set("c", "true")); sum.Rejected != 1 {
		t.Fatalf("summary of the first load = %+v, want tenant a refused", sum)
	}
	before, _ := tenantHealth(r, "a")
	if before.Rejected == nil || before.Rejected.Stage != "export" {
		t.Fatalf("health of a after the first load = %+v, want a refusal at stage export", before)
	}

	sum := loadSets(notGlobal, set("c", "false"))

	after, _ := tenantHealth(r, "a")
	if sum.Rejected != 0 {
		t.Errorf("summary of a load that changes only tenant c = %+v, want no refusal counted", sum)
	}
	if after.Rejected != before.Rejected {
		t.Errorf("refusal of a after a load that changes only tenant c = %p %+v, want the same %p", after.Rejected,
			after.Rejected, before.Rejected)
	}
}
