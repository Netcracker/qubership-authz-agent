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

package server

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"authz-agent/internal/costcheck"
)

// deepBodyNesting is how many levels deep the resource of a request body
// nests, 1 Mi (1048576): far past any depth limit a JSON decoder may set. A
// level of a list takes two bytes, so the body of about 2 MiB stays under the
// body limit of the test app, Fiber's default of 4 MiB.
const deepBodyNesting = 1 << 20

// knownDeepBodyCrashes lists the routes whose body still kills the process
// when its resource nests deepBodyNesting levels deep, by the name of the
// case.
var knownDeepBodyCrashes = map[string]costcheck.Known{}

// A request body whose resource nests 1 Mi levels deep is refused or
// answered, and the process survives. The same body nested one level deep is
// answered, so that a route that refuses every body still fails its case.
func TestARequestBodyNestedDeepFailsTheRequest(t *testing.T) {
	cases := []struct {
		name, path string
		// body returns the request body whose resource is resource.
		body func(resource string) string
		want string
	}{
		{"a check of one resource", "/access/v1/check/resource",
			func(r string) string { return `{"type":"ORDER","operation":"READ","resource":` + r + `}` },
			"200 true"},
		{"a bulk check", "/access/v1/check/resource/bulk",
			func(r string) string { return `[{"id":"x","type":"ORDER","operation":"READ","resource":` + r + `}]` },
			`200 ["x"]`},
		{"a bulk check of operations", "/access/v1/check/resource/bulk/operations",
			func(r string) string { return `[{"id":"x","type":"ORDER","operations":["READ"],"resource":` + r + `}]` },
			`200 {"READ":["x"]}`},
		{"a check of one resource, v2", "/access/v2/check/resource",
			func(r string) string { return `{"type":"ORDER","operation":"READ","resource":` + r + `}` },
			`200 {"decision":true}`},
		{"a bulk check of operations, v2", "/access/v2/check/resource/bulk/operations",
			func(r string) string {
				return `{"type":"ORDER","entries":[{"id":"x","operations":["READ"],"resource":` + r + `}]}`
			},
			`200 {"decision":{"READ":["x"]}}`},
		{"a bulk check of operations, preview v1", "/preview/v1/check/resource/bulk/operations",
			func(r string) string { return `[{"id":"x","type":"ORDER","operations":["READ"],"resource":` + r + `}]` },
			`200 {"READ":["x"]}`},
		{"a bulk check of operations, preview v2", "/preview/v2/check/resource/bulk/operations",
			func(r string) string {
				return `{"type":"ORDER","entries":[{"id":"x","operations":["READ"],"resource":` + r + `}]}`
			},
			`200 {"decision":{"READ":["x"]}}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			nested := func(n int) string { return `{"a":` + strings.Repeat("[", n) + "1" + strings.Repeat("]", n) + "}" }
			app := newPublicApp(t)
			if code, body, _ := call(t, app, http.MethodPost, tc.path, tc.body(nested(1)), admin); fmt.Sprint(code, " ", body) != tc.want {
				t.Fatalf("POST %s with the resource nested one level deep = %d %s, want %s", tc.path, code, body, tc.want)
			}
			costcheck.Deep(t, knownDeepBodyCrashes[tc.name], func() {
				call(t, app, http.MethodPost, tc.path, tc.body(nested(deepBodyNesting)), admin)
			})
		})
	}
}
