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

package paritysuite

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"
)

// DomainSeeder owns the profile-specific wipe + seed lifecycle for one
// parity-suite run.
type DomainSeeder interface {
	WipeDomain(ctx context.Context, domain string) error
	SeedDomain(ctx context.Context, domain string, fixtureRoot fs.FS) error
}

// legacyPapSeeder preserves the Step 3 legacy PAP lifecycle byte-for-byte.
type legacyPapSeeder struct {
	cfg    Config
	tokens *TokenFactory
}

// authzAgentInternalSeeder targets authz-agent's internal pap-client upload
// endpoints. Domain and tenant are accepted by the suite config for parity with
// the legacy path but are no-ops on this profile.
type authzAgentInternalSeeder struct {
	cfg Config
}

type regularPolicyFixture struct {
	externalID string
	body       any
}

type simplifiedPolicyFixture struct {
	path  string
	items []any
}

// NewDomainSeeder builds a seeder bound to the suite config and token source.
// A nil TokenFactory falls back to a fresh one using the same PARITY_* config.
func NewDomainSeeder(cfg Config, tokens *TokenFactory) DomainSeeder {
	if tokens == nil {
		tokens = NewTokenFactory(cfg)
	}
	if isAuthzAgentProfile(cfg.Profile) {
		return &authzAgentInternalSeeder{cfg: cfg}
	}
	return &legacyPapSeeder{cfg: cfg, tokens: tokens}
}

// WipeDomain clears both simplified policies and simplified PIPs for the
// given domain using the same PAP bulk-overwrite semantics the old ac-seed
// shell script relied on.
func WipeDomain(ctx context.Context, cfg Config, domain string) error {
	return NewDomainSeeder(cfg, nil).WipeDomain(ctx, domain)
}

// SeedDomain bulk-loads the given fixture tree into the target domain. The FS
// may contain simplified smoke fixtures, simplified suite fixtures, and/or the
// regular full-policy pack under policies/regular/*.json.
func SeedDomain(ctx context.Context, cfg Config, domain string, fixtureRoot fs.FS) error {
	return NewDomainSeeder(cfg, nil).SeedDomain(ctx, domain, fixtureRoot)
}

func (ds *legacyPapSeeder) WipeDomain(ctx context.Context, domain string) error {
	token, err := ds.tokens.M2MToken()
	if err != nil {
		return fmt.Errorf("mint M2M token for wipe: %w", err)
	}
	if err := ds.putSimplifiedArray(ctx, domain, true, token, []any{}); err != nil {
		return fmt.Errorf("wipe policies for domain %s: %w", domain, err)
	}
	if err := ds.putSimplifiedArray(ctx, domain, false, token, []any{}); err != nil {
		return fmt.Errorf("wipe pips for domain %s: %w", domain, err)
	}
	return nil
}

func (ds *legacyPapSeeder) SeedDomain(ctx context.Context, domain string, fixtureRoot fs.FS) error {
	token, err := ds.tokens.M2MToken()
	if err != nil {
		return fmt.Errorf("mint M2M token for seed: %w", err)
	}

	policies, pips, regular, err := loadFixturePayloads(fixtureRoot)
	if err != nil {
		return err
	}

	if len(pips) > 0 {
		if err := ds.putSimplifiedArray(ctx, domain, false, token, pips); err != nil {
			return fmt.Errorf("seed PIPs for domain %s: %w", domain, err)
		}
	}
	if len(policies) > 0 {
		if err := ds.putSimplifiedArray(ctx, domain, true, token, policies); err != nil {
			return fmt.Errorf("seed policies for domain %s: %w", domain, err)
		}
	}
	for _, fixture := range regular {
		if err := ds.putRegularPolicy(ctx, token, fixture); err != nil {
			return fmt.Errorf("seed regular policy %s: %w", fixture.externalID, err)
		}
	}
	return nil
}

func (ds *legacyPapSeeder) putSimplifiedArray(ctx context.Context, domain string, policies bool, token string, payload []any) error {
	kind := "domainPIPs"
	if policies {
		kind = "domainPolicies"
	}
	endpoint := buildURL(
		ds.cfg.ACBaseURL,
		"/access/v1/simplifiedPolicies/"+kind+"/"+url.PathEscape(domain),
		url.Values{"tenant_id": []string{ds.cfg.TenantID}}.Encode(),
	)
	return ds.putJSON(ctx, endpoint, token, payload)
}

func (ds *legacyPapSeeder) putRegularPolicy(ctx context.Context, token string, fixture regularPolicyFixture) error {
	endpoint := buildURL(
		ds.cfg.ACBaseURL,
		"/access/v1/policySets/externalId/"+url.PathEscape(fixture.externalID),
		url.Values{"tenant_id": []string{ds.cfg.TenantID}}.Encode(),
	)
	return ds.putJSON(ctx, endpoint, token, fixture.body)
}

func (ds *legacyPapSeeder) putJSON(ctx context.Context, endpoint, token string, payload any) error {
	req, err := buildRequest(ctx, http.MethodPut, endpoint, payload, TokenBundle{M2M: token}, PerCallOptions{})
	if err != nil {
		return err
	}
	status, raw, err := doRequest(req)
	if err != nil {
		return err
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("status=%d body=%s", status, strings.TrimSpace(string(raw)))
	}
	return nil
}

// pullSettleDelay is how long to wait after writing to the authz-policy-admin before the
// agent can be assumed to have applied the change.
//
// Writing to the stub is not the same as loading into the agent, which is the
// substantive difference between this seeder and the legacy one. The legacy
// seeder PUT straight at access-control's PAP and the decision path saw the new
// policies on the next request; here the seeder writes to a stub and the agent's
// PolicyPuller picks it up on its own tick (authz-agent-ADR-0071). Nothing in
// the suite waits for that tick, so without this delay SetupSuite seeds and
// immediately asserts against whatever the agent still holds.
//
// The delay is the pull interval plus a margin for the fetch, conversion and
// PUT into OPA. It must stay >= AUTHZ_PAP_CLIENT_PULL_INTERVAL in
// tests/parity/compose/docker-compose.authz-agent.yml (1 s there, so 2 s here).
// Raise PARITY_PULL_SETTLE_SECONDS if that interval is raised, or on a slow
// machine where the conversion of a large fixture set overruns the margin.
//
// This is a wait, not a poll, for the same reason the runtime suite's
// waitForACPull is: the agent exposes no "applied revision" that a poll could
// compare against, so a poll would have to guess a decision outcome and would
// then be indistinguishable from the assertion it precedes.
func pullSettleDelay() time.Duration {
	if raw := strings.TrimSpace(os.Getenv("PARITY_PULL_SETTLE_SECONDS")); raw != "" {
		if secs, err := strconv.Atoi(raw); err == nil && secs >= 0 {
			return time.Duration(secs) * time.Second
		}
	}
	return 2 * time.Second
}

// awaitPull blocks for pullSettleDelay, honouring ctx cancellation.
func awaitPull(ctx context.Context) {
	select {
	case <-ctx.Done():
	case <-time.After(pullSettleDelay()):
	}
}

func (ds *authzAgentInternalSeeder) WipeDomain(ctx context.Context, domain string) error {
	if err := ds.putACStub(ctx, simplifiedPath("domainPolicies", domain), []any{}); err != nil {
		return fmt.Errorf("wipe policies: %w", err)
	}
	if err := ds.putACStub(ctx, simplifiedPath("domainPIPs", domain), []any{}); err != nil {
		return fmt.Errorf("wipe pips: %w", err)
	}
	awaitPull(ctx)
	return nil
}

func (ds *authzAgentInternalSeeder) SeedDomain(ctx context.Context, domain string, fixtureRoot fs.FS) error {
	policyFixtures, pipList, regular, err := loadAuthzInternalFixturePayloads(fixtureRoot)
	if err != nil {
		return err
	}

	if len(pipList) > 0 {
		if err := ds.putACStub(ctx, simplifiedPath("domainPIPs", domain), pipList); err != nil {
			return fmt.Errorf("seed pips: %w", err)
		}
	}
	if len(policyFixtures) > 0 {
		// Collect all fixtures into one array and upload in a single call.
		// The stub replaces the whole domain atomically so the pull loop
		// always sees a consistent snapshot.
		var all []any
		for _, fixture := range policyFixtures {
			all = append(all, fixture.items...)
		}
		if err := ds.putACStub(ctx, simplifiedPath("domainPolicies", domain), all); err != nil {
			return fmt.Errorf("seed policies: %w", err)
		}
	}
	if len(regular) > 0 {
		fmt.Printf("[paritysuite] authz-agent seeder: skipped %d regular full-policy fixture(s) under policies/regular (D-AA-E)\n", len(regular))
	}
	awaitPull(ctx)
	return nil
}

// simplifiedPath builds access-control's simplified-policy path for a domain.
// The stub serves these paths verbatim (authz-agent-ADR-0073), so this seeder and
// the legacy access-control seeder above now address the same URLs.
func simplifiedPath(kind, domain string) string {
	return "/access/v1/simplifiedPolicies/" + kind + "/" + url.PathEscape(domain)
}

func (ds *authzAgentInternalSeeder) putACStub(ctx context.Context, path string, payload any) error {
	req, err := buildRequest(
		ctx,
		http.MethodPut,
		buildURL(ds.cfg.ACStubBaseURL, path, ""),
		payload,
		TokenBundle{},
		PerCallOptions{},
	)
	if err != nil {
		return err
	}

	status, raw, err := doRequest(req)
	if err != nil {
		return err
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("status=%d body=%s", status, strings.TrimSpace(string(raw)))
	}
	return nil
}

func loadFixturePayloads(root fs.FS) ([]any, []any, []regularPolicyFixture, error) {
	policyFixtures, pips, regular, err := loadAuthzInternalFixturePayloads(root)
	if err != nil {
		return nil, nil, nil, err
	}

	var policies []any
	for _, fixture := range policyFixtures {
		policies = append(policies, fixture.items...)
	}
	return policies, pips, regular, nil
}

func loadAuthzInternalFixturePayloads(root fs.FS) ([]simplifiedPolicyFixture, []any, []regularPolicyFixture, error) {
	var paths []string
	if err := fs.WalkDir(root, ".", func(rel string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if strings.HasSuffix(strings.ToLower(rel), ".json") {
			paths = append(paths, rel)
		}
		return nil
	}); err != nil {
		return nil, nil, nil, fmt.Errorf("walk fixture tree: %w", err)
	}
	sort.Strings(paths)

	var (
		policyFixtures []simplifiedPolicyFixture
		smokePips      []any
		suitePips      []any
		regular        []regularPolicyFixture
	)

	for _, rel := range paths {
		raw, err := fs.ReadFile(root, rel)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("read fixture %s: %w", rel, err)
		}
		cleaned, err := sanitizeFixtureJSON(raw)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("sanitize fixture %s: %w", rel, err)
		}

		switch {
		case strings.HasPrefix(rel, "regular/"), strings.HasPrefix(rel, "policies/regular/"):
			externalID := strings.TrimSuffix(path.Base(rel), path.Ext(rel))
			regular = append(regular, regularPolicyFixture{externalID: externalID, body: cleaned})
		case strings.HasSuffix(rel, "-pips.json"):
			items, ok := cleaned.([]any)
			if !ok {
				return nil, nil, nil, fmt.Errorf("fixture %s must decode to a JSON array", rel)
			}
			if strings.HasPrefix(rel, "smoke/") {
				smokePips = append(smokePips, items...)
				continue
			}
			suitePips = append(suitePips, items...)
		default:
			items, ok := cleaned.([]any)
			if !ok {
				return nil, nil, nil, fmt.Errorf("fixture %s must decode to a JSON array", rel)
			}
			policyFixtures = append(policyFixtures, simplifiedPolicyFixture{path: rel, items: items})
		}
	}

	return policyFixtures, append(smokePips, suitePips...), regular, nil
}

func sanitizeFixtureJSON(raw []byte) (any, error) {
	var decoded any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return nil, err
	}
	return stripCommentFields(decoded), nil
}

func stripCommentFields(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(typed))
		for k, v := range typed {
			if k == "_comment" {
				continue
			}
			out[k] = stripCommentFields(v)
		}
		return out
	case []any:
		out := make([]any, 0, len(typed))
		for _, item := range typed {
			out = append(out, stripCommentFields(item))
		}
		return out
	default:
		return value
	}
}
