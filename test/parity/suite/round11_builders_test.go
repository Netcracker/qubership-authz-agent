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

import (
	"context"
	"net/http"
	"strings"
	"time"
)

// The builders below were written for round 11, whose cases are partly data
// under testdata/cases/round11 now, and the round 11 functions still in Go and
// later rounds build their cases with them.

// round11ResourceType is the resource type of the isolated case keyed key.
func round11ResourceType(key string) string {
	return "PARITY_SUITE_R11_" + strings.ToUpper(strings.ReplaceAll(key, "-", "_"))
}

// round11NestedSetCase builds a DENY_OVERRIDES set of round9PredicatePolicy
// and the set nested builds, and sends requests.
func round11NestedSetCase(id string, nested func(b regularBuilder) map[string]any, requests []isolatedRequest) regularCase {
	b := regularBuilder{caseID: id}
	rt := regularResourceType(id)
	return regularCase{
		id:           id,
		resourceType: rt,
		uploads: []regularUpload{{externalID: "parity-" + id, sets: []any{
			b.set("outer", "resourceType == '"+rt+"'", "DENY_OVERRIDES", []any{round9PredicatePolicy(b)}, []any{nested(b)}),
		}}},
		requests: requests,
	}
}

// scopeOutsideIterateCase builds a set that reads subject.permissionScope
// without iterating: IS EMPTY over the scope key on READ, the same on the left of
// a true OR on UPDATE, and IS NULL over it on PROBE. withControl adds to the same
// policy a rule on CONTROL whose condition is true and reads no scope, and on
// MIXED a rule under IS EMPTY over the scope key beside a rule whose condition is
// true, with a request on each of the two operations.
func scopeOutsideIterateCase(id string, withControl bool) regularCase {
	b := regularBuilder{caseID: id}
	rt := regularResourceType(id)
	rules := []any{
		b.rule("region-is-empty", "operation == 'READ'", "subject.permissionScope.region IS EMPTY", "ALLOW", nil),
		b.rule("region-is-empty-or-true", "operation == 'UPDATE'", "subject.permissionScope.region IS EMPTY OR resource.a == 'y'", "ALLOW", nil),
		b.rule("region-is-null", "operation == 'PROBE'", "subject.permissionScope.region IS NULL", "ALLOW", nil),
	}
	requests := []isolatedRequest{
		{name: "read-under-is-empty", resource: map[string]any{"id": "r11-scope-outside"}},
		{name: "update-under-is-empty-or-true", operation: "UPDATE", resource: map[string]any{"id": "r11-scope-outside", "a": "y"}},
		{name: "probe-under-is-null", operation: "PROBE", resource: map[string]any{"id": "r11-scope-outside"}},
	}
	if withControl {
		rules = append(rules,
			b.rule("control-without-scope", "operation == 'CONTROL'", "true", "ALLOW", nil),
			b.rule("mixed-region-is-empty", "operation == 'MIXED'", "subject.permissionScope.region IS EMPTY", "ALLOW", nil),
			b.rule("mixed-true", "operation == 'MIXED'", "true", "ALLOW", nil))
		requests = append(requests,
			isolatedRequest{name: "control-without-scope", operation: "CONTROL", resource: map[string]any{"id": "r11-scope-outside"}},
			isolatedRequest{name: "scope-read-beside-a-true-rule", operation: "MIXED", resource: map[string]any{"id": "r11-scope-outside"}})
	}
	return regularCase{
		id:           id,
		resourceType: rt,
		pips:         []any{permissionScopeWirePIP},
		uploads: []regularUpload{{externalID: "parity-" + id, sets: []any{
			b.set("set", "resourceType == '"+rt+"'", "DENY_UNLESS_PERMIT", []any{
				b.policy("scoped", readerTarget, "DENY_UNLESS_PERMIT", rules...),
			}, nil),
		}}},
		requests: requests,
	}
}

// pinTwoScopeGrants pins the scope service to two grants for parity-reader,
// region r1 and region r2, and waits out the cachePeriod of
// permissionScopeWirePIP, as permission-scope-wire does.
func (s *ParitySuite) pinTwoScopeGrants() {
	s.Require().NoError(s.pipMock.PinRoute(context.Background(), permissionScopeWirePath(parityReaderSubjectID), PipStubResponse{
		StatusCode: http.StatusOK,
		Body:       permissionScopeWireBody(parityReaderSubjectID, []permissionScopeGrant{{"region": {"r1"}}, {"region": {"r2"}}}),
	}))
	time.Sleep(2 * time.Second)
}
