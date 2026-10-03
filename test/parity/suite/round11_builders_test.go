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
	"strings"
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
