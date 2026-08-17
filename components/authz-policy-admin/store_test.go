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

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	policiesPath = "/access/v1/simplifiedPolicies/domainPolicies/"
	pipsPath     = "/access/v1/simplifiedPolicies/domainPIPs/"
)

const bssPolicies = `[
  {"component":"BSS","resourceType":"Invoice","operation":"READ","roles":["ROLE_ADMIN"]}
]`

const ossPolicies = `[
  {"component":"OSS","resourceType":"Ticket","operation":"UPDATE","roles":["ROLE_ENGINEER"]}
]`

func newTestServer(t *testing.T, dataDir string) *http.ServeMux {
	t.Helper()
	st, err := newStore(dataDir)
	if err != nil {
		t.Fatalf("newStore: %v", err)
	}
	mux := http.NewServeMux()
	(&server{st: st}).routes(mux)
	return mux
}

func do(t *testing.T, mux *http.ServeMux, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer test")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

// Uploading one domain must not disturb another. This is the whole reason the
// store is keyed by the domain from the request path rather than holding one flat
// list: access-control scopes `PUT .../domainPolicies/BSS` to BSS, and the export
// the agent pulls is the union.
func TestDomainsAreIndependentAndExportIsTheUnion(t *testing.T) {
	mux := newTestServer(t, t.TempDir())

	if rec := do(t, mux, http.MethodPut, policiesPath+"BSS", bssPolicies); rec.Code != http.StatusOK {
		t.Fatalf("BSS upload: got %d, body %s", rec.Code, rec.Body.String())
	}
	if rec := do(t, mux, http.MethodPut, policiesPath+"OSS", ossPolicies); rec.Code != http.StatusOK {
		t.Fatalf("OSS upload: got %d, body %s", rec.Code, rec.Body.String())
	}

	// Each domain still reads back its own content.
	for domain, want := range map[string]string{"BSS": "Invoice", "OSS": "Ticket"} {
		rec := do(t, mux, http.MethodGet, policiesPath+domain, "")
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s: got %d", domain, rec.Code)
		}
		var items []simplifiedPolicy
		decode(t, rec.Body.Bytes(), &items)
		if len(items) != 1 || items[0].ResourceType != want {
			t.Errorf("GET %s returned %+v, want one policy on %s", domain, items, want)
		}
	}

	// The v3 export carries both, so the agent applies both.
	var resp v3PolicySetsResponse
	decode(t, do(t, mux, http.MethodGet, "/access/v3/config/policySets", "").Body.Bytes(), &resp)
	domains := map[string]bool{}
	for _, ps := range resp.PolicySets {
		domains[ps.Domain] = true
	}
	if !domains["BSS"] || !domains["OSS"] {
		t.Errorf("v3 export covers %v, want both BSS and OSS", domains)
	}
}

// An unknown domain reads as an empty collection, which is what access-control
// answers for a domain nobody has uploaded yet.
func TestUnknownDomainReadsEmpty(t *testing.T) {
	mux := newTestServer(t, t.TempDir())
	rec := do(t, mux, http.MethodGet, policiesPath+"NOPE", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d, want 200", rec.Code)
	}
	var items []simplifiedPolicy
	decode(t, rec.Body.Bytes(), &items)
	if len(items) != 0 {
		t.Errorf("got %d policies for an unused domain, want 0", len(items))
	}
}

// A restart must serve exactly the same policies under exactly the same hash:
// the puller caches the hash it applied, so a hash that changed for no reason
// costs a needless re-push, and a hash that repeated over different data would
// hide a real change.
func TestStoreReloadsPersistedDomainsWithSameHash(t *testing.T) {
	dir := t.TempDir()

	first := newTestServer(t, dir)
	do(t, first, http.MethodPut, policiesPath+"BSS", bssPolicies)
	do(t, first, http.MethodPut, policiesPath+"OSS", ossPolicies)
	do(t, first, http.MethodPut, pipsPath+"BSS", `[{"name":"tenant","pipType":"TOKEN","claim":"tenant_id"}]`)
	before := hashOf(t, first)

	second := newTestServer(t, dir)
	if got := hashOf(t, second); got != before {
		t.Errorf("hash changed across restart: %q → %q", before, got)
	}
	var resp v3PolicySetsResponse
	decode(t, do(t, second, http.MethodGet, "/access/v3/config/policySets", "").Body.Bytes(), &resp)
	if len(resp.PolicySets) != 2 {
		t.Errorf("reloaded %d policy sets, want 2 (one per domain)", len(resp.PolicySets))
	}

	raw, err := os.ReadFile(filepath.Join(dir, policiesFilePrefix+"BSS.json"))
	if err != nil {
		t.Fatalf("read persisted file: %v", err)
	}
	if string(raw) != bssPolicies {
		t.Errorf("persisted file is not the uploaded body verbatim:\n%s", raw)
	}
}

// The hash identifies content, not upload count: re-uploading the same policies
// formatted differently must not make the puller re-apply them.
func TestHashIsContentBased(t *testing.T) {
	mux := newTestServer(t, t.TempDir())

	do(t, mux, http.MethodPut, policiesPath+"BSS", bssPolicies)
	original := hashOf(t, mux)

	reformatted := `[{"operation":"READ","roles":["ROLE_ADMIN"],"resourceType":"Invoice","component":"BSS"}]`
	do(t, mux, http.MethodPut, policiesPath+"BSS", reformatted)
	if got := hashOf(t, mux); got != original {
		t.Errorf("hash changed on a semantically identical upload: %q → %q", original, got)
	}

	changed := `[{"component":"BSS","resourceType":"Invoice","operation":"UPDATE","roles":["ROLE_ADMIN"]}]`
	do(t, mux, http.MethodPut, policiesPath+"BSS", changed)
	if got := hashOf(t, mux); got == original {
		t.Errorf("hash unchanged after the policies changed: %q", got)
	}
}

// Policies and PIPs carry independent hashes, so a PIP upload does not make the
// puller believe the policy set changed.
func TestPolicyAndPIPHashesAreIndependent(t *testing.T) {
	mux := newTestServer(t, t.TempDir())

	do(t, mux, http.MethodPut, policiesPath+"BSS", bssPolicies)
	policiesHash := hashOf(t, mux)

	do(t, mux, http.MethodPut, pipsPath+"BSS", `[{"name":"tenant","pipType":"TOKEN","claim":"tenant_id"}]`)
	if got := hashOf(t, mux); got != policiesHash {
		t.Errorf("policy hash moved on a PIP upload: %q → %q", policiesHash, got)
	}

	var pipsResp v3PIPsResponse
	decode(t, do(t, mux, http.MethodGet, "/access/v3/config/pips", "").Body.Bytes(), &pipsResp)
	if pipsResp.Hash == policiesHash {
		t.Error("PIP and policy hashes are identical; they must be computed per collection")
	}
}

// An upload that cannot be persisted must be reported as a failure and must
// leave the served content untouched — a 200 whose data disappears on the next
// restart is the failure mode this ordering exists to prevent.
func TestFailedPersistKeepsPreviousContent(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	dir := t.TempDir()
	mux := newTestServer(t, dir)
	do(t, mux, http.MethodPut, policiesPath+"BSS", bssPolicies)
	before := hashOf(t, mux)

	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	if rec := do(t, mux, http.MethodPut, policiesPath+"BSS", `[]`); rec.Code != http.StatusInternalServerError {
		t.Fatalf("got %d, want 500 when the data dir is read-only", rec.Code)
	}
	if got := hashOf(t, mux); got != before {
		t.Errorf("served content changed despite the failed write: %q → %q", before, got)
	}
	// A brand-new domain must not linger in memory either.
	if rec := do(t, mux, http.MethodPut, policiesPath+"FRESH", ossPolicies); rec.Code != http.StatusInternalServerError {
		t.Fatalf("got %d for a new domain, want 500", rec.Code)
	}
	var items []simplifiedPolicy
	decode(t, do(t, mux, http.MethodGet, policiesPath+"FRESH", "").Body.Bytes(), &items)
	if len(items) != 0 {
		t.Errorf("failed upload of a new domain left %d policies behind", len(items))
	}
}

func TestNewStoreRejectsUnwritableDir(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	if _, err := newStore(dir); err == nil {
		t.Fatal("newStore accepted a read-only data dir; the Pod must fail fast instead")
	}
}

// A SIGKILL between CreateTemp and Rename leaves a temp file behind. On a small
// PVC these would accumulate for the lifetime of the volume.
func TestNewStoreSweepsStaleTempFiles(t *testing.T) {
	dir := t.TempDir()
	stale := filepath.Join(dir, ".acstub-deadbeef.json")
	if err := os.WriteFile(stale, []byte("{}"), 0o644); err != nil {
		t.Fatalf("seed stale file: %v", err)
	}
	if _, err := newStore(dir); err != nil {
		t.Fatalf("newStore: %v", err)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Errorf("stale temp file survived startup: %v", err)
	}
}

// Malformed persisted data must not take the container down, and must not take
// the other domains with it: the file stays as evidence and its domain is empty.
func TestMalformedDomainFileSkipsOnlyThatDomain(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, policiesFilePrefix+"BROKEN.json")
	if err := os.WriteFile(bad, []byte("{not json"), 0o644); err != nil {
		t.Fatalf("seed file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, policiesFilePrefix+"BSS.json"), []byte(bssPolicies), 0o644); err != nil {
		t.Fatalf("seed file: %v", err)
	}

	mux := newTestServer(t, dir)
	var resp v3PolicySetsResponse
	decode(t, do(t, mux, http.MethodGet, "/access/v3/config/policySets", "").Body.Bytes(), &resp)
	if len(resp.PolicySets) != 1 || resp.PolicySets[0].Domain != "BSS" {
		t.Errorf("got %+v, want only the BSS policy set", resp.PolicySets)
	}
	if _, err := os.Stat(bad); err != nil {
		t.Errorf("malformed file was removed; it should be kept as evidence: %v", err)
	}
}

// The domain lands in a file name, so anything that could escape the data
// directory is refused rather than sanitised into a different domain.
func TestInvalidDomainIsRejected(t *testing.T) {
	mux := newTestServer(t, t.TempDir())

	// Reach the handler and fail validation.
	for _, domain := range []string{"has%20space", "sub%2Fdir", "quote%27", strings.Repeat("x", 65)} {
		rec := do(t, mux, http.MethodPut, policiesPath+domain, bssPolicies)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("domain %q: got %d, want 400", domain, rec.Code)
		}
	}

	// `.` and `..` never reach the handler: net/http cleans the path first and
	// answers a redirect. Either way no file is written for them.
	for _, domain := range []string{".", ".."} {
		rec := do(t, mux, http.MethodPut, policiesPath+domain, bssPolicies)
		if rec.Code == http.StatusOK {
			t.Errorf("domain %q was accepted (%d)", domain, rec.Code)
		}
	}
}

// access-control serves POST / PATCH / DELETE on the PIP path. This stub does
// not, and says so with 405 and an Allow header instead of a silent 404.
func TestUnsupportedMethodsAnswer405(t *testing.T) {
	mux := newTestServer(t, t.TempDir())
	for _, tc := range []struct{ method, path string }{
		{http.MethodPost, pipsPath + "BSS"},
		{http.MethodPatch, pipsPath + "BSS"},
		{http.MethodDelete, pipsPath + "BSS"},
		{http.MethodPost, policiesPath + "BSS"},
	} {
		rec := do(t, mux, tc.method, tc.path, `[]`)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s %s: got %d, want 405", tc.method, tc.path, rec.Code)
		}
		if allow := rec.Header().Get("Allow"); allow != "GET, PUT" {
			t.Errorf("%s %s: Allow header %q, want \"GET, PUT\"", tc.method, tc.path, allow)
		}
	}
}

// The v3 export is the agent's entry point and must keep rejecting an anonymous
// caller, because the real access-control does.
func TestV3ExportRequiresAuthorizationHeader(t *testing.T) {
	mux := newTestServer(t, t.TempDir())
	for _, p := range []string{"/access/v3/config/policySets", "/access/v3/config/pips"} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, p, nil))
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s without Authorization: got %d, want 401", p, rec.Code)
		}
	}
}

// In-memory mode (no AUTHZ_POLICY_ADMIN_DATA_DIR) is what the Compose test stacks run:
// uploads must work with no data directory at all.
func TestInMemoryModeServesUploads(t *testing.T) {
	mux := newTestServer(t, "")
	if rec := do(t, mux, http.MethodPut, policiesPath+"BSS", bssPolicies); rec.Code != http.StatusOK {
		t.Fatalf("upload: got %d, body %s", rec.Code, rec.Body.String())
	}
	var resp v3PolicySetsResponse
	decode(t, do(t, mux, http.MethodGet, "/access/v3/config/policySets", "").Body.Bytes(), &resp)
	if len(resp.PolicySets) != 1 {
		t.Errorf("got %d policy sets, want 1", len(resp.PolicySets))
	}
}

// The health probe reports the domains it holds, which is the first thing anyone
// debugging "my policies did not arrive" wants to see.
func TestHashEndpointListsDomains(t *testing.T) {
	mux := newTestServer(t, t.TempDir())
	do(t, mux, http.MethodPut, policiesPath+"BSS", bssPolicies)
	do(t, mux, http.MethodPut, pipsPath+"OSS", `[]`)

	var status struct {
		Domains []string `json:"domains"`
		Hash    string   `json:"hash"`
	}
	decode(t, do(t, mux, http.MethodGet, "/authz-policy-admin/hash", "").Body.Bytes(), &status)
	if fmt.Sprint(status.Domains) != "[BSS OSS]" {
		t.Errorf("domains %v, want [BSS OSS]", status.Domains)
	}
	if status.Hash == "" {
		t.Error("hash is empty")
	}
}

func hashOf(t *testing.T, mux *http.ServeMux) string {
	t.Helper()
	var resp v3PolicySetsResponse
	decode(t, do(t, mux, http.MethodGet, "/access/v3/config/policySets", "").Body.Bytes(), &resp)
	return resp.Hash
}

func decode(t *testing.T, raw []byte, into any) {
	t.Helper()
	if err := json.Unmarshal(raw, into); err != nil {
		t.Fatalf("decode response: %v (%s)", err, raw)
	}
}
