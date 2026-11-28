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

package regogen

import (
	"errors"
	"slices"
	"testing"

	"authz-agent/internal/jsonvalue"
	"authz-agent/internal/regogen/spectables"
)

// An entry of knownOutsideDomain that no resolver reaches any more fails the
// test, so a fix of the defect it names removes the entry too.
func TestResolvedStatesStayInTheDomainOfTheirKind(t *testing.T) {
	tab := table(t)
	const pips = `{"name": "subject.tok", "pipType": "TOKEN", "claim": "c"},
		{"name": "subject.tok0", "pipType": "TOKEN", "claim": "absent", "defaultValue": false},
		{"name": "subject.hdr", "pipType": "HEADER", "header": "X-H"},
		{"name": "subject.map", "pipType": "MAPPING", "subjectKey": "subject.name", "mapping": {}},
		{"name": "subject.gen", "pipType": "GENERAL", "url": "http://g"}`
	conditions := []string{
		"subject.permissionScope IS EMPTY",
		"subject.permissionScope == 'x'",
		"subject.isM2M == true",
		"subject.roles CONTAINS 'x'",
		"subject.permissions CONTAINS 'x'",
		"subject.tok == 'x'",
		"subject.tok0 == 'x'",
		"subject.hdr == 'x'",
		"subject.map == 'x'",
		"subject.gen == 'x'",
		"subject.entitledResources.of('T').as('r') CONTAINS resource.id",
	}
	claimSets := []string{`{}`, `{"c": "x"}`, `{"c": null}`, `{"c": [1, {"a": 2}]}`}
	reached := map[kindState]bool{}
	for _, cond := range conditions {
		for _, claims := range claimSets {
			t.Run(cond+" with claims "+claims, func(t *testing.T) {
				m, err := Generate(tenantWithSetAndPIPs(t, "PERMIT_UNLESS_DENY", "ALLOW", cond, pips), tab, DefaultOptions())
				if err != nil {
					t.Fatalf("Generate: %v", err)
				}
				req := Request{
					Body:    Body{Operation: "read", ResourceType: "doc"},
					Claims:  mustDecode(t, claims).(*jsonvalue.Object),
					Headers: map[string]string{"x-h": "x"},
				}
				m.ResolveSubject(&req)
				for _, r := range m.Refs {
					v, ok := req.Values[r.Key]
					if !ok {
						continue
					}
					dom, ok := tab.Domain(r.Kind)
					if !ok {
						t.Errorf("kind %s of %s has no domain", r.Kind, r.Key)
						continue
					}
					if slices.Contains(dom.States, v.State) {
						continue
					}
					ks := kindState{r.Kind, v.State}
					if reason, known := knownOutsideDomain[ks]; known {
						reached[ks] = true
						t.Logf("known defect: ResolveSubject set %s (kind %s) to %s, outside its domain %v: %s",
							r.Key, r.Kind, v.State, dom.States, reason)
						continue
					}
					t.Errorf("ResolveSubject set %s (kind %s) to %s, outside its domain %v", r.Key, r.Kind, v.State, dom.States)
				}
			})
		}
	}
	for ks, reason := range knownOutsideDomain {
		if !reached[ks] {
			t.Errorf("remove the entry for kind %s and state %s from knownOutsideDomain: no resolver gives it any more (%s)",
				ks.kind, ks.state, reason)
		}
	}
}

func TestAStateOutsideTheDomainOfItsKindFailsTheRequestAndOneInsideDoesNot(t *testing.T) {
	const pip = `{"name": "subject.r", "pipType": "TOKEN", "claim": "c"}`
	m, err := Generate(tenantWithSetAndPIPs(t, "DENY_UNLESS_PERMIT", "ALLOW", "subject.r == 'x'", pip),
		table(t), DefaultOptions())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if dom, _ := table(t).Domain(spectables.KindPIPToken); slices.Contains(dom.States, spectables.StateScopeOutside) {
		t.Fatalf("the domain of %s holds %s, so the request below tests nothing", spectables.KindPIPToken, spectables.StateScopeOutside)
	}
	for _, tc := range []struct {
		name    string
		v       Resolved
		wantErr error
	}{
		{"SCOPE_OUTSIDE, which a TOKEN PIP cannot hold", Resolved{State: spectables.StateScopeOutside}, errOutsideDomain},
		{"VALUE", Resolved{State: spectables.StateValue, Value: "x"}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := Request{Body: Body{Operation: "read", ResourceType: "doc"}, Values: map[string]Resolved{keyR: tc.v}}
			if _, err := Project(m, req); !errors.Is(err, tc.wantErr) {
				t.Errorf("Project with subject.r in state %s: error %v, want %v", tc.v.State, err, tc.wantErr)
			}
		})
	}
}
