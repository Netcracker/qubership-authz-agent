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

// The builders below were written for round 13, whose cases are data under
// testdata/cases/round13 now, and round 14 still builds its Go cases with them.

// round13ScopeShapes are the three answers of the scope service the round 13
// iterate cases run under: no grants, one grant of r1, and two grants of r1 and
// r2.
var round13ScopeShapes = []struct {
	name   string
	grants []permissionScopeGrant
}{
	{"no-grants", nil},
	{"one-grant-r1", []permissionScopeGrant{{"region": {"r1"}}}},
	{"two-grants-r1-and-r2", []permissionScopeGrant{{"region": {"r1"}}, {"region": {"r2"}}}},
}

// round13RegionRequests are the filter on LIST and check/resource on LIST in the
// regions r1 and r2.
var round13RegionRequests = []isolatedRequest{
	{name: "filter", filter: true},
	{name: "check-list-in-region-r1", operation: "LIST", resource: map[string]any{"id": "r13-iterate", "region": "r1"}},
	{name: "check-list-in-region-r2", operation: "LIST", resource: map[string]any{"id": "r13-iterate", "region": "r2"}},
}

// round13ScopedPolicy is the policy of scope-set-algorithm under policyAlgorithm:
// one LIST rule whose target is subject.permissionScope.region IS NOT NULL,
// whose condition is subject.permissionScope.region CONTAINS resource.region, and
// whose predicate is region=in=(${subject.permissionScope.region}).
func round13ScopedPolicy(b regularBuilder, key, policyAlgorithm string) map[string]any {
	return b.policy(key, readerTarget, policyAlgorithm,
		b.rule(key+"-region-granted",
			"operation == 'LIST' AND subject.permissionScope.region IS NOT NULL",
			"subject.permissionScope.region CONTAINS resource.region",
			"ALLOW", map[string]string{"rsqlPredicate": "region=in=(${subject.permissionScope.region})"}))
}

// round13IteratingSet is a policy set under setAlgorithm whose iterate node over
// subject.permissionScope is under nodeAlgorithm, unlike
// regularBuilder.iteratingSet, which gives both one algorithm.
func round13IteratingSet(b regularBuilder, key, target, setAlgorithm, nodeAlgorithm string, policies, nested []any) map[string]any {
	set := b.set(key, target, setAlgorithm, emptyIfNil(policies), nested)
	set["iterate"] = map[string]any{"foreach": "subject.permissionScope", "combiningAlgorithm": nodeAlgorithm}
	return set
}
