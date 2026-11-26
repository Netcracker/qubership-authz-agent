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
	"flag"
	"fmt"
	"maps"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/gofiber/fiber/v2"
	"go.yaml.in/yaml/v3"
)

// specPath is the OpenAPI description of the public surface.
const specPath = "../../../../api/openapi.yaml"

// knownSpecDrift lists the requests and answers of this package's tests that
// api/openapi.yaml does not declare today, keyed by the case name
// checkAgainstSpec reports. Each entry is a known defect: the test logs it
// instead of failing, and TestMain fails once the entry no longer matches
// any request, so that the change that fixes the defect also removes the
// entry.
var knownSpecDrift = map[string]string{
	"POST /access/v1/check/resource/bulk/operations: query tenant_id": "F41: the bulk/operations routes " +
		"read tenant_id, and the spec does not declare it on them",
	"POST /access/v1/check/resource: header Tenant": "F41: the check routes read the Tenant header, " +
		"and the spec declares it on none of them",
	"POST /access/v1/check/resource: status 500": "N-E6: a check route answers 500 when the admission " +
		"policy cannot be evaluated, and the spec declares 500 on no route",
	"POST /access/v1/check/resource: header X-Request-Id": "N-E8: the public routes read X-Request-Id " +
		"and echo it in the response, and the spec declares it on none of them",
	"GET /health: status 500": "N-E7: a panicking handler answers 500, and the spec of the public /health " +
		"declares only 200 and 503",
}

// headersOfEveryRoute are the request headers the spec leaves to HTTP: no
// operation declares them, and every route accepts them.
var headersOfEveryRoute = map[string]bool{
	"accept":         true,
	"content-length": true,
	"content-type":   true,
}

type specParameter struct {
	Ref  string `yaml:"$ref"`
	Name string `yaml:"name"`
	In   string `yaml:"in"`
}

type specOperation struct {
	Parameters []specParameter        `yaml:"parameters"`
	Responses  map[string]yaml.Node   `yaml:"responses"`
	Security   *[]map[string][]string `yaml:"security"`
}

type specDocument struct {
	Paths      map[string]map[string]yaml.Node `yaml:"paths"`
	Security   []map[string][]string           `yaml:"security"`
	Components struct {
		Parameters map[string]specParameter `yaml:"parameters"`
	} `yaml:"components"`
}

var (
	specOnce   sync.Once
	spec       specDocument
	specErr    error
	driftMu    sync.Mutex
	driftFound = map[string]bool{}
)

func loadSpec(t *testing.T) *specDocument {
	t.Helper()
	specOnce.Do(func() {
		raw, err := os.ReadFile(specPath)
		if err != nil {
			specErr = err
			return
		}
		specErr = yaml.Unmarshal(raw, &spec)
		if specErr == nil && len(spec.Paths) == 0 {
			specErr = fmt.Errorf("%s declares no paths", specPath)
		}
	})
	if specErr != nil {
		t.Fatalf("load %s: %v", specPath, specErr)
	}
	return &spec
}

// isPublic reports whether app serves the public surface, the one
// api/openapi.yaml describes; the internal surface serves its own /health.
func isPublic(app *fiber.App) bool {
	return slices.ContainsFunc(app.GetRoutes(true), func(r fiber.Route) bool {
		return r.Path == "/access/v1/check/resource"
	})
}

// operation returns the operation of the spec for method and path, and the
// parameters it declares, path-level ones included, as "in:name" with the
// name in lower case; header:authorization is among them where the
// operation requires security. ok is false where the spec has no such
// operation.
func (d *specDocument) operation(t *testing.T, method, path string) (op specOperation, declared map[string]bool, ok bool) {
	t.Helper()
	item, ok := d.Paths[path]
	if !ok {
		return op, nil, false
	}
	node, ok := item[strings.ToLower(method)]
	if !ok {
		return op, nil, false
	}
	if err := node.Decode(&op); err != nil {
		t.Fatalf("%s %s in %s: %v", method, path, specPath, err)
	}
	params := op.Parameters
	if shared, ok := item["parameters"]; ok {
		var more []specParameter
		if err := shared.Decode(&more); err != nil {
			t.Fatalf("parameters of %s in %s: %v", path, specPath, err)
		}
		params = append(params, more...)
	}
	declared = map[string]bool{}
	for _, p := range params {
		if p.Ref != "" {
			p = d.Components.Parameters[strings.TrimPrefix(p.Ref, "#/components/parameters/")]
		}
		declared[p.In+":"+strings.ToLower(p.Name)] = true
	}
	security := d.Security
	if op.Security != nil {
		security = *op.Security
	}
	if len(security) > 0 {
		declared["header:authorization"] = true
	}
	return op, declared, true
}

// checkAgainstSpec fails t unless the spec declares, on the operation req
// was sent to, every query parameter and every header of req outside
// headersOfEveryRoute, and the status the app answered. A case
// knownSpecDrift lists is logged instead. A request the spec
// has no operation for, such as a probe of an unknown path or a method the
// route refuses, is not checked; neither is a request to an app that does
// not serve the public surface.
func checkAgainstSpec(t *testing.T, app *fiber.App, req *http.Request, status int) {
	t.Helper()
	if !isPublic(app) {
		return
	}
	op, declared, ok := loadSpec(t).operation(t, req.Method, req.URL.Path)
	if !ok {
		return
	}
	prefix := req.Method + " " + req.URL.Path + ": "
	var found []string
	for name := range req.URL.Query() {
		if !declared["query:"+strings.ToLower(name)] {
			found = append(found, prefix+"query "+name)
		}
	}
	for name := range req.Header {
		lower := strings.ToLower(name)
		if !headersOfEveryRoute[lower] && !declared["header:"+lower] {
			found = append(found, prefix+"header "+name)
		}
	}
	if _, ok := op.Responses[strconv.Itoa(status)]; !ok {
		if _, ok := op.Responses["default"]; !ok {
			found = append(found, prefix+"status "+strconv.Itoa(status))
		}
	}
	slices.Sort(found)
	for _, name := range found {
		driftMu.Lock()
		driftFound[name] = true
		driftMu.Unlock()
		if defect, ok := knownSpecDrift[name]; ok {
			t.Logf("known spec drift %q (%s)", name, defect)
			continue
		}
		t.Errorf("%s: api/openapi.yaml does not declare it on this operation", name)
	}
}

// TestMain runs the tests and then fails the run for every entry of
// knownSpecDrift that no request matched. It skips that step where -run,
// -skip, or -list leaves tests out, because the request that matches an
// entry may be in a test that did not run.
func TestMain(m *testing.M) {
	flag.Parse()
	code := m.Run()
	if code != 0 || slices.ContainsFunc([]string{"test.run", "test.skip", "test.list"}, func(name string) bool {
		return flag.Lookup(name).Value.String() != ""
	}) {
		os.Exit(code)
	}
	for _, name := range slices.Sorted(maps.Keys(knownSpecDrift)) {
		if !driftFound[name] {
			fmt.Fprintf(os.Stderr, "FAIL: %q no longer drifts from api/openapi.yaml; remove it from knownSpecDrift\n", name)
			code = 1
		}
	}
	os.Exit(code)
}

// The public surface registers the paths api/openapi.yaml declares, and no
// other: a path the spec leaves out is one no generated client can call.
func TestSpecConformance_ThePublicRoutesAreThePathsOfTheSpec(t *testing.T) {
	declared := slices.Sorted(maps.Keys(loadSpec(t).Paths))
	routes := map[string]bool{}
	for _, r := range newPublicApp(t).GetRoutes(true) {
		if r.Path != "/" { // the middleware app.Use installs
			routes[r.Path] = true
		}
	}
	for _, path := range declared {
		if !routes[path] {
			t.Errorf("%s declares %s, and the public app does not register it", specPath, path)
		}
	}
	for _, path := range slices.Sorted(maps.Keys(routes)) {
		if !slices.Contains(declared, path) {
			t.Errorf("the public app registers %s, and %s does not declare it", path, specPath)
		}
	}
}
