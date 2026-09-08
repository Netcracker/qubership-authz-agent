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

package engine

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/open-policy-agent/opa/v1/topdown/builtins"

	"authz-agent/policies"
)

const testModule = `package t

import rego.v1

allow if input.x == 1

roles := data.policies.roles

when := time.now_ns()
`

func newTestEngine(t *testing.T, dataDirs ...string) *Engine {
	t.Helper()
	e, err := New(Options{Modules: map[string]string{"t.rego": testModule}, DataDirs: dataDirs, Ignore: []string{"..*"}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return e
}

// TestEval_InputAndUndefined: a rule that holds evaluates to its value and an
// undefined document reports ok=false rather than an error.
func TestEval_InputAndUndefined(t *testing.T) {
	e := newTestEngine(t)
	ctx := context.Background()
	v, ok, err := e.Eval(ctx, []string{"t", "allow"}, map[string]any{"x": 1}, nil)
	if err != nil || !ok || v != true {
		t.Fatalf("allow with x=1: v=%v ok=%v err=%v", v, ok, err)
	}
	_, ok, err = e.Eval(ctx, []string{"t", "allow"}, map[string]any{"x": 2}, nil)
	if err != nil || ok {
		t.Fatalf("allow with x=2 must be undefined: ok=%v err=%v", ok, err)
	}
	_, ok, err = e.Eval(ctx, []string{"nothing", "here"}, nil, nil)
	if err != nil || ok {
		t.Fatalf("unknown document must be undefined: ok=%v err=%v", ok, err)
	}
}

// TestPutGetPatch_DocumentsReachTheRules: documents written through Put and
// Patch are what the rules read, and Get returns them as stored.
func TestPutGetPatch_DocumentsReachTheRules(t *testing.T) {
	e := newTestEngine(t)
	ctx := context.Background()
	if err := e.Put(ctx, []string{"policies"}, map[string]any{"roles": []any{"a"}}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	v, ok, err := e.Eval(ctx, []string{"t", "roles"}, nil, nil)
	if err != nil || !ok {
		t.Fatalf("roles after Put: ok=%v err=%v", ok, err)
	}
	if got := v.([]any); len(got) != 1 || got[0] != "a" {
		t.Fatalf("roles = %v, want [a]", got)
	}
	err = e.Patch(ctx, []string{"policies"}, []PatchOp{{Op: "add", Path: "/roles", Value: []any{"a", "b"}}})
	if err != nil {
		t.Fatalf("Patch: %v", err)
	}
	stored, ok, err := e.Get(ctx, []string{"policies", "roles"})
	if err != nil || !ok || len(stored.([]any)) != 2 {
		t.Fatalf("Get after Patch: %v ok=%v err=%v", stored, ok, err)
	}
	if err := e.Put(ctx, []string{"deep", "er", "doc"}, "x"); err != nil {
		t.Fatalf("Put with parents: %v", err)
	}
	if _, ok, _ := e.Get(ctx, []string{"deep", "er", "doc"}); !ok {
		t.Fatal("nested document not found after Put")
	}
}

// TestPatch_MissingDocumentIsNotFound: patching a document that does not exist
// fails with the not-found error the data API maps to 404, so a writer can
// fall back to a full PUT.
func TestPatch_MissingDocumentIsNotFound(t *testing.T) {
	e := newTestEngine(t)
	err := e.Patch(context.Background(), []string{"authn"}, []PatchOp{{Op: "add", Path: "/x", Value: 1}})
	if err == nil || !IsNotFound(err) {
		t.Fatalf("Patch on a missing document: err=%v, want not found", err)
	}
	if err := e.Patch(context.Background(), []string{"authn"}, []PatchOp{{Op: "move", Path: "/x"}}); err == nil {
		t.Fatal("unsupported op must fail")
	}
}

// TestNDBuiltinCache_RecordsTimeNow: the cache handed to Eval collects the
// non-deterministic builtins the rules called, which the decision log
// carries so a decision can be replayed.
func TestNDBuiltinCache_RecordsTimeNow(t *testing.T) {
	e := newTestEngine(t)
	ndbc := builtins.NDBCache{}
	if _, ok, err := e.Eval(context.Background(), []string{"t", "when"}, nil, ndbc); err != nil || !ok {
		t.Fatalf("when: ok=%v err=%v", ok, err)
	}
	if _, ok := ndbc["time.now_ns"]; !ok {
		t.Fatalf("nd_builtin_cache lacks time.now_ns: %v", ndbc)
	}
}

// TestNew_DataDirsSeedTheStore: JSON files under a data directory land at the
// path of their directory, and names matching Ignore are skipped, like the
// `..data` entries of a ConfigMap mount.
func TestNew_DataDirsSeedTheStore(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "authn"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "policies.json"), []byte(`{"policies": {"roles": ["r"]}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "authn", "jwks.json"), []byte(`{"jwksByKid": {"k": {}}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "..data"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "..data", "stale.json"), []byte(`{"stale": true}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ignored.rego"), []byte("package ignored\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	e := newTestEngine(t, dir)
	ctx := context.Background()
	if v, ok, _ := e.Eval(ctx, []string{"t", "roles"}, nil, nil); !ok || len(v.([]any)) != 1 {
		t.Fatalf("roles from the data dir: %v ok=%v", v, ok)
	}
	if _, ok, _ := e.Get(ctx, []string{"authn", "jwksByKid", "k"}); !ok {
		t.Fatal("authn/jwks.json did not land under data.authn")
	}
	if _, ok, _ := e.Get(ctx, []string{"stale"}); ok {
		t.Fatal("..data must be ignored")
	}
}

// TestNew_RejectsBrokenPolicy: a module that does not compile fails New with
// the compiler's message rather than a nil engine.
func TestNew_RejectsBrokenPolicy(t *testing.T) {
	if _, err := New(Options{Modules: map[string]string{"bad.rego": "package bad\n\nx := undefined_fn()\n"}}); err == nil {
		t.Fatal("broken policy must fail New")
	}
	if _, err := New(Options{}); err == nil {
		t.Fatal("no modules must fail New")
	}
}

// TestNew_EmbeddedProductPoliciesCompile: the policies the service ships
// compile on the library, and system.authz answers a write with the secret
// the way the OPA server's authorizer expected it to.
func TestNew_EmbeddedProductPoliciesCompile(t *testing.T) {
	modules, err := policies.Modules()
	if err != nil {
		t.Fatal(err)
	}
	e, err := New(Options{Modules: modules})
	if err != nil {
		t.Fatalf("New with product policies: %v", err)
	}
	ctx := context.Background()
	if err := e.Put(ctx, []string{"opa_auth_secret"}, "s3cr3t"); err != nil {
		t.Fatal(err)
	}
	allowed := func(input map[string]any) bool {
		v, ok, err := e.Eval(ctx, []string{"system", "authz", "allow"}, input, nil)
		if err != nil {
			t.Fatalf("system.authz: %v", err)
		}
		return ok && v == true
	}
	if !allowed(map[string]any{"method": "PUT", "path": []any{"v1", "data", "policies"}, "identity": "s3cr3t", "params": map[string]any{}}) {
		t.Error("PUT with the secret must be allowed")
	}
	if allowed(map[string]any{"method": "PUT", "path": []any{"v1", "data", "policies"}, "params": map[string]any{}}) {
		t.Error("PUT without identity must be denied")
	}
	if !allowed(map[string]any{"method": "POST", "path": []any{"v1", "data", "authorize"}, "params": map[string]any{}}) {
		t.Error("POST authorize must be open")
	}
	if allowed(map[string]any{"method": "POST", "path": []any{"v1", "data", "authorize"}, "params": map[string]any{"explain": []any{"full"}}}) {
		t.Error("POST authorize with explain must be denied")
	}
}

// TestQuery_EscapesSegments: segments become bracketed string keys, so a
// dash or a quote in a document name cannot change the query.
func TestQuery_EscapesSegments(t *testing.T) {
	if got, want := Query([]string{"opa-lockdown-test", `a"b`}), `data["opa-lockdown-test"]["a\"b"]`; got != want {
		t.Fatalf("Query = %s, want %s", got, want)
	}
}
