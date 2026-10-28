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

// pipCacheCacheableCaseID names the cacheable case; the resource type of its set
// and the ids of its elements derive from it.
const pipCacheCacheableCaseID = "pip-cache-cacheable-true"

// pipCacheCacheableRoute is the pip-mock path pipCacheCacheablePIP reads.
const pipCacheCacheableRoute = "/api/v1/pip/r9-cache-cacheable"

// pipCacheCacheablePIP is pipCachePIP with cacheable true and no cachePeriod,
// under a name and a path of its own.
var pipCacheCacheablePIP = map[string]any{
	"name":              "subject.parityR9CacheCacheable",
	"url":               parityPipMockBase + "/r9-cache-cacheable",
	"httpMethod":        "POST",
	"pipType":           "GENERAL",
	"type":              "JSON",
	"jsonPath":          "$.value",
	"requestAttributes": map[string]string{"resourceType": regularResourceType(pipCacheCacheableCaseID)},
	"cacheable":         true,
}

// How long access-control serves a GENERAL PIP declared cacheable with no
// cachePeriod from its cache. pip-cache-cacheable-false records one call per
// request for a declaration that is not cacheable; a cacheable one is not
// recorded, and a cache that keeps an answer across requests is the one thing
// an evaluator with no cache would differ in only by its call count.
//
// The rounds are pip-cache-cacheable-false's: v1 and one READ, the control that
// the PIP is read; then v2, and READ and PROBE 5 seconds and again 70 seconds
// after the change. In each pair exactly one answer is true: READ while the
// cached v1 is served, PROBE once pip-mock was asked again. The call count of
// every request is logged.
//
// The case lives in its own test function so that a recording run can be
// filtered to it and leave every golden already committed alone. Legacy profile
// only, like every regular case.
func (s *ParitySuite) TestRound9PIPCacheCacheableCases() {
	if isAuthzAgentProfile(s.cfg.Profile) {
		s.T().Skip("regular policy sets are evaluated by access-control only; authz-agent loads simplified policies")
	}
	s.runPIPCacheCase(pipCacheCacheableCaseID, pipCacheCacheableRoute, pipCacheCacheablePIP)
}
