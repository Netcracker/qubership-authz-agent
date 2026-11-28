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
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"

	"authz-agent/components/authz-agent/internal/snapshot"
	"authz-agent/internal/jsonvalue"
)

// bigResource is a resource of about 256 KiB whose member b is "x" and whose
// list a holds one element with x "z" after 16000 others.
var bigResource = `{"b":"x","a":[` + strings.Repeat(`{"x":"yyyyyyyy"},`, 16000) + `{"x":"z"}]}`

// allocated returns the bytes the request of body to path allocates, the
// least of three runs, and fails the test unless the answer is 200. The
// answer is not checked against the API specification, whose check would
// count.
func allocated(t *testing.T, app *fiber.App, path, body string) uint64 {
	t.Helper()
	least := uint64(math.MaxUint64)
	for range 3 {
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		code, got, _ := send(t, app, http.MethodPost, path, body, admin, false)
		runtime.ReadMemStats(&after)
		if code != http.StatusOK {
			t.Fatalf("POST %s = %d %.200s, want 200", path, code, got)
		}
		least = min(least, after.TotalAlloc-before.TotalAlloc)
	}
	return least
}

// inTenantA is the options of a service that decides in tenant a by default
// over reg.
func inTenantA(reg *snapshot.Registry) Options {
	return Options{Snapshots: reg, DefaultTenant: func() string { return "a" }}
}

// operations is a JSON list of n copies of the operation op.
func operations(op string, n int) string {
	return "[" + strings.TrimSuffix(strings.Repeat(op+",", n), ",") + "]"
}

// The operations of one bulk/operations item share its resource, so an
// item of 100 operations allocates about what one operation does, whether
// the policy reads a member of the resource, a jsonPath filter, a deep
// scan, or a PIP whose request reads the resource, and whatever the
// operations are.
func TestBulkOperations_TheCostOfAnItemDoesNotGrowWithItsOperations(t *testing.T) {
	routes := []struct {
		name, path string
		body       func(ops string) string
	}{
		{"v1", "/access/v1/check/resource/bulk/operations",
			func(ops string) string {
				return `[{"id":"1","type":"doc","operations":` + ops + `,"resource":` + bigResource + `}]`
			}},
		{"v2", "/access/v2/check/resource/bulk/operations",
			func(ops string) string {
				return `{"type":"doc","entries":[{"id":"1","operations":` + ops + `,"resource":` + bigResource + `}]}`
			}},
	}
	pip := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		_, _ = w.Write([]byte(`"x"`))
	}))
	t.Cleanup(pip.Close)
	readsTheResource := `{"pips": [{"tenantId": "a", "name": "subject.g", "pipType": "GENERAL", "httpMethod": "POST",
		"url": "` + pip.URL + `/${resource.b}", "requestAttributes": {"list": "${resource.a}", "op": "${operation}"}}]}`
	for _, cond := range []struct{ name, condition, pips string }{
		{"a member", "resource.b == 'x'", `{"pips": []}`},
		{"a jsonPath filter", "resource.a[?(@.x == 'z')].x == 'z'", `{"pips": []}`},
		{"a deep scan", "resource..x == 'z'", `{"pips": []}`},
		{"a PIP whose request reads the resource", "subject.g == 'x'", readsTheResource},
	} {
		reg := registryWithPIPs(t, `{"policySets": [`+tenantSet("a", cond.condition)+`]}`, cond.pips)
		app := newPublicAppOver(t, map[string]string{"internals.rego": admissionStub}, inTenantA(reg))
		for _, route := range routes {
			for _, op := range []string{`"read"`, `""`} {
				t.Run(cond.name+"/"+route.name+"/operation "+op, func(t *testing.T) {
					one := allocated(t, app, route.path, route.body(operations(op, 1)))
					hundred := allocated(t, app, route.path, route.body(operations(op, 100)))
					if hundred > 3*one {
						t.Errorf("POST %s with 100 operations %s allocated %d KiB, %.1f times the %d KiB of one; want at most 3 times",
							route.path, op, hundred>>10, float64(hundred)/float64(one), one>>10)
					}
				})
			}
		}
	}
}

// Items that carry different resources are decided each on its own
// resource, also where the policy reads a path of the resource lazily.
func TestBulkOperations_EachItemIsDecidedOnItsOwnResource(t *testing.T) {
	for _, condition := range []string{"resource.b == 'x'", "resource..secret IS NOT NULL"} {
		t.Run(condition, func(t *testing.T) {
			reg := registry(t, `{"policySets": [`+tenantSet("a", condition)+`]}`)
			app := newPublicAppOver(t, map[string]string{"internals.rego": admissionStub}, inTenantA(reg))
			const body = `[{"id":"x","type":"doc","operations":["read","write"],"resource":{"b":"x","c":{"secret":1}}},
				{"id":"y","type":"doc","operations":["read","write"],"resource":{"b":"y","c":{}}},
				{"id":"z","type":"doc","operations":["read"],"resource":{"b":"x","secret":2}}]`
			const want = `{"read":["x","z"],"write":[]}`
			code, got, _ := call(t, app, http.MethodPost, "/access/v1/check/resource/bulk/operations", body, admin)
			if code != http.StatusOK || got != want {
				t.Errorf("POST bulk/operations = %d %s, want 200 %s", code, got, want)
			}
		})
	}
}

// The admission policies read no resource, so a check of a resource of
// about 1 MiB allocates at most twice what decoding the resource
// once allocates.
func TestCheckResource_TheAdmissionDoesNotCopyTheResource(t *testing.T) {
	resource := `{"b":"x","a":[` + strings.Repeat(`{"x":"yyyyyyyy"},`, 64000) + `{"x":"z"}]}`
	reg := registry(t, `{"policySets": [`+tenantSet("a", "resource.b == 'x'")+`]}`)
	app := newPublicAppOver(t, map[string]string{"internals.rego": admissionStub}, inTenantA(reg))
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	if _, err := jsonvalue.Decode([]byte(resource)); err != nil {
		t.Fatal(err)
	}
	runtime.ReadMemStats(&after)
	decode := after.TotalAlloc - before.TotalAlloc
	for _, tc := range []struct{ name, path, body string }{
		{"check/resource", "/access/v1/check/resource",
			`{"type":"doc","operation":"read","resource":` + resource + `}`},
		{"check/resource/bulk", "/access/v1/check/resource/bulk",
			`[{"id":"1","type":"doc","operation":"read","resource":` + resource + `}]`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := allocated(t, app, tc.path, tc.body); got > 2*decode {
				t.Errorf("POST %s allocated %d KiB, %.1f times the %d KiB of decoding the resource; want at most 2 times",
					tc.path, got>>10, float64(got)/float64(decode), decode>>10)
			}
		})
	}
}
