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

package policyadmin

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"authz-agent/internal/acconfig"
	"authz-agent/internal/atomicfile"
	"authz-agent/internal/pips"
	"authz-agent/internal/simplifiedpolicies"
)

const (
	// DefaultPullInterval is the default polling period for access-control.
	// Interval-based polling is used rather than long-poll because it is
	// simpler, does not require gateway-level timeout allowances, and is
	// consistent with how ProvidersReloader works.  See ADR-0071.
	DefaultPullInterval = 30 * time.Second

	// DefaultPullHTTPTimeout is the per-request timeout for policy-set and
	// PIP fetches.
	DefaultPullHTTPTimeout = 30 * time.Second

	// DefaultACTokenFile is the default path of the projected service-account
	// token. Overridden by AUTHZ_PAP_CLIENT_TOKEN_FILE.
	DefaultACTokenFile = "/etc/authz/ac-token/token"

	// PolicyMountDir is the path watched for a mounted ConfigMap that delivers
	// policies in simplified format. When this directory exists at startup,
	// the pull loop is disabled and the mount path is used instead.
	// Must be outside /etc/opa/data which is a writable emptyDir.
	PolicyMountDir = "/etc/authz/policies"
)

// PullConfig holds all configuration for the PolicyPuller.
type PullConfig struct {
	// SourceURL is the base URL of the access-control service.
	// Example: "http://access-control:8080". Empty → pull loop disabled.
	SourceURL string

	// Interval is how often to poll. 0 → disabled.
	Interval time.Duration

	// TokenFile is the path to the Bearer token file, re-read per request so
	// that projected service-account tokens (rotated in-place by the kubelet)
	// are always current.
	TokenFile string

	// PolicyFile is the path to write the normalised policy document on disk.
	PolicyFile string

	// PIPFile is the path to write the normalised PIP document on disk.
	PIPFile string

	// OPAPoliciesURL is the OPA data API URL for policies.
	// Example: "http://127.0.0.1:8181/v1/data/policies"
	OPAPoliciesURL string

	// OPAPIPsURL is the OPA data API URL for PIPs.
	// Example: "http://127.0.0.1:8181/v1/data/pips"
	OPAPIPsURL string

	// Entitlements is the container-pinned entitlements PIP config (ADR-0054).
	// nil → no entitlements entry in the normalised document.
	Entitlements *pips.EntitlementsConfig

	// HTTPTimeout overrides DefaultPullHTTPTimeout when positive.
	HTTPTimeout time.Duration

	// OPAAuthToken is the bearer token sent to OPA on every write request
	// (PUT /v1/data/*). Empty → no Authorization header on OPA writes.
	// This token is used exclusively for OPA writes; policy-source fetches
	// (access-control / authz-policy-admin) use a separate plain client so the OPA
	// secret never reaches an external service. See authz-agent-ADR-0077.
	OPAAuthToken string

	// PullStatusFile is the path where PolicyPuller writes the pull status
	// (PullStatus JSON) after the first successful pull and after each
	// subsequent pull.  The file is also written immediately with
	// policiesLoaded=true when pull is disabled (empty SourceURL or zero
	// Interval) so that the readiness probe does not block a Pod that was
	// never expected to pull.  Empty → status not written.
	PullStatusFile string

	// Logger receives all diagnostic output.
	Logger *log.Logger
}

// PolicyPuller periodically fetches policies and PIPs from access-control's
// v3 config API, converts them to the simplified model, and publishes the
// result to OPA without restarting the Pod.
//
// There is no change detection: every tick fetches, converts, and republishes
// unconditionally. The v3 envelope carries `hash` and `lastModificationTimestamp`
// fields that look like change signals, but access-control froze both in October
// 2025 — the database triggers that maintained them were dropped on purpose and
// never restored, so on every supported build they are constants that never move
// when policies are written. Keying on them made the agent serve its first-seen
// configuration forever. See docs/parity/access-control-v3-config-hash-contract.md
// and authz-agent-ADR-0079.
//
// Every pull is a full replace — the v3 API has no tombstones.
//
// On any failure the previous data stays live in OPA; the error is logged
// and retried on the next tick.
//
// Two separate HTTP clients are used: pullClient (plain, no auth injection)
// for access-control / authz-policy-admin fetches, and opaClient (OPAAuthTransport) for
// OPA data-API writes. This ensures the OPA write secret never reaches any
// external policy source. See authz-agent-ADR-0077.
type PolicyPuller struct {
	cfg        PullConfig
	pullClient *http.Client // plain client for policy-source fetches
	opaClient  *http.Client // OPA-auth client for OPA data-API writes
	logger     *log.Logger

	// firstSuccessAt is the time of the first successful pull.
	// Zero value means no successful pull yet.
	firstSuccessAt time.Time

	// lastConversion holds the counts from the most recent conversion so that
	// they are still reported when a later tick fails before converting.
	// Nil until the first apply.
	lastConversion *ConversionStats
}

// NewPolicyPuller constructs a PolicyPuller.
func NewPolicyPuller(cfg PullConfig) *PolicyPuller {
	logger := cfg.Logger
	if logger == nil {
		logger = log.New(os.Stdout, "[policy-pull] ", log.LstdFlags)
	}
	timeout := cfg.HTTPTimeout
	if timeout <= 0 {
		timeout = DefaultPullHTTPTimeout
	}
	return &PolicyPuller{
		cfg:        cfg,
		pullClient: &http.Client{Timeout: timeout},
		opaClient:  NewOPAClient(cfg.OPAAuthToken, timeout),
		logger:     logger,
	}
}

// Run polls until ctx is cancelled.  It should be started as a goroutine next
// to the pap-client HTTP server.  Returns immediately when SourceURL or
// Interval is not set.
//
// Pull status (PullStatus JSON at cfg.PullStatusFile) is written:
//   - Immediately with policiesLoaded=true when pull is disabled, so that the
//     "pap-client healthcheck --readiness" probe does not block a Pod that
//     will never pull.
//   - After every successful PullOnce call; the policiesLoaded flag is a latch
//     that is never reset to false even if subsequent pulls fail.
func (p *PolicyPuller) Run(ctx context.Context) {
	if strings.TrimSpace(p.cfg.SourceURL) == "" {
		p.logger.Printf("policy pull disabled: AUTHZ_PAP_CLIENT_SOURCE_URL not set")
		p.writePullStatusDisabled("pull disabled: source URL empty")
		return
	}
	if p.cfg.Interval <= 0 {
		p.logger.Printf("policy pull disabled: interval is 0")
		p.writePullStatusDisabled("pull disabled: interval is 0")
		return
	}

	p.logger.Printf("pulling policies from %s every %s", p.cfg.SourceURL, p.cfg.Interval)

	// Perform an immediate pull at startup so policies are available before
	// the first ticker fires.
	if err := p.PullOnce(ctx); err != nil {
		p.logger.Printf("warn: initial policy pull failed: %v", err)
	} else {
		p.recordPullSuccess()
	}

	ticker := time.NewTicker(p.cfg.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := p.PullOnce(ctx); err != nil {
				p.logger.Printf("warn: policy pull failed, keeping previous data: %v", err)
			} else {
				p.recordPullSuccess()
			}
		}
	}
}

// recordPullSuccess is called after a successful PullOnce.  It writes the pull
// status file on the first call (setting firstSuccessAt) and updates
// lastSuccessAt on subsequent calls.  policiesLoaded is never reset to false.
func (p *PolicyPuller) recordPullSuccess() {
	now := time.Now().UTC()
	nowStr := now.Format(time.RFC3339)
	if p.firstSuccessAt.IsZero() {
		p.firstSuccessAt = now
	}
	status := PullStatus{
		PoliciesLoaded: true,
		FirstSuccessAt: p.firstSuccessAt.UTC().Format(time.RFC3339),
		LastSuccessAt:  nowStr,
		Conversion:     p.lastConversion,
	}
	if err := WritePullStatus(p.cfg.PullStatusFile, status); err != nil {
		p.logger.Printf("warn: failed to write pull status: %v", err)
	}
}

// writePullStatusDisabled writes policiesLoaded=true with a reason when the
// pull loop exits early (disabled configuration).  This prevents the readiness
// probe from blocking a Pod that was never expected to pull policies.
func (p *PolicyPuller) writePullStatusDisabled(reason string) {
	status := PullStatus{
		PoliciesLoaded: true,
		Reason:         reason,
	}
	if err := WritePullStatus(p.cfg.PullStatusFile, status); err != nil {
		p.logger.Printf("warn: failed to write pull status: %v", err)
	}
}

// PullOnce fetches both configs and republishes them unconditionally.
// Returns nil on success; an error when a fetch or publish failed (previous
// data still live in OPA).
func (p *PolicyPuller) PullOnce(ctx context.Context) error {
	token, err := p.readToken()
	if err != nil {
		return fmt.Errorf("read token: %w", err)
	}

	psRaw, err := p.fetchURL(ctx, p.cfg.SourceURL+"/access/v3/config/policySets", token)
	if err != nil {
		return fmt.Errorf("fetch policySets: %w", err)
	}

	pipRaw, err := p.fetchURL(ctx, p.cfg.SourceURL+"/access/v3/config/pips", token)
	if err != nil {
		return fmt.Errorf("fetch pips: %w", err)
	}

	return p.applyAndPublish(ctx, psRaw, pipRaw)
}

// applyAndPublish converts, persists, and pushes both configs to OPA.
func (p *PolicyPuller) applyAndPublish(ctx context.Context, psRaw []byte, pipRaw []byte) error {
	// 1. Convert v3 export → simplified model.
	policyList, convStats, err := acconfig.ConvertPolicySets(psRaw, p.logger)
	if err != nil {
		return fmt.Errorf("convert policySets: %w", err)
	}
	p.lastConversion = &ConversionStats{
		PolicySets:        convStats.PolicySets,
		PolicySetsSkipped: convStats.PolicySetsSkipped,
		Rules:             convStats.Rules,
		RulesSkipped:      convStats.RulesSkipped,
		RulesDenySkipped:  convStats.RulesDenySkipped,
		Policies:          convStats.Policies,
	}
	if convStats.RulesSkipped > 0 || convStats.PolicySetsSkipped > 0 {
		// One line an operator can act on, instead of one warn per skipped rule
		// buried in thousands. Individual warnings stay for diagnosis.
		p.logger.Printf("warn: acconfig conversion dropped data: %d/%d policy sets and %d/%d rules could not be converted (%d policies produced)",
			convStats.PolicySetsSkipped, convStats.PolicySets,
			convStats.RulesSkipped, convStats.Rules, convStats.Policies)
	}
	pipList, err := acconfig.ConvertPIPs(pipRaw, p.logger)
	if err != nil {
		return fmt.Errorf("convert pips: %w", err)
	}

	// 2. Normalise.
	normalizedPolicies, err := simplifiedpolicies.NormalizePolicies(policyList)
	if err != nil {
		return fmt.Errorf("normalize policies: %w", err)
	}
	pipDoc, _, err := pips.NormalizeItems(pipList)
	if err != nil {
		return fmt.Errorf("normalize pips: %w", err)
	}

	// 3. Apply container-pinned entitlements (ADR-0054).
	pips.ApplyEntitlementsOverride(pipDoc, p.cfg.Entitlements)

	// 4. Persist policies to disk FIRST — BuildActivationIndex reads from
	// the policy file, so the file must be written before the index is built.
	if err := p.persistPolicies(normalizedPolicies); err != nil {
		return fmt.Errorf("persist policies: %w", err)
	}

	// 5. Build GENERAL-PIP activation index against the freshly-written file.
	activation := pips.BuildActivationIndex(pipDoc.Normalized.Remote.General, p.cfg.PolicyFile)
	pipDoc.Normalized.Activation.GeneralByResourceTypeOperation = activation

	// 6. Persist PIPs (with correct activation).
	if err := p.persistPIPs(pipDoc); err != nil {
		return fmt.Errorf("persist pips: %w", err)
	}

	// 7. Push both to OPA.
	if err := p.pushPoliciesToOPA(ctx, normalizedPolicies); err != nil {
		return fmt.Errorf("push policies to OPA: %w", err)
	}
	if err := p.pushPIPsToOPA(ctx, &pipDoc.Normalized); err != nil {
		return fmt.Errorf("push pips to OPA: %w", err)
	}

	// Count from the conversion, not from normalizedPolicies: the latter is the
	// normalised OPA document (a handful of top-level keys), so its length is
	// not a policy count and reads as a catastrophic data loss when it is.
	p.logger.Printf("policies updated (%d policies, %d PIPs)",
		convStats.Policies, len(pipList))
	return nil
}

// fetchURL performs a GET with the given Bearer token and returns the raw body.
func (p *PolicyPuller) fetchURL(ctx context.Context, url, token string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := p.pullClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return nil, fmt.Errorf("read response from %s: %w", url, err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("%s: HTTP %d: %s",
			url, resp.StatusCode, strings.TrimSpace(string(raw)))
	}

	return raw, nil
}

// readToken reads the Bearer token from the configured file.
// The file is re-read on every call because projected service-account tokens
// are rotated in place by the kubelet.
func (p *PolicyPuller) readToken() (string, error) {
	path := strings.TrimSpace(p.cfg.TokenFile)
	if path == "" {
		return "", nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			// Token file not yet present (first boot): proceed without a token;
			// the server will reject with 401 and we will retry next tick.
			return "", nil
		}
		return "", err
	}
	return strings.TrimSpace(string(raw)), nil
}

// persistPolicies writes the normalised policy map to disk wrapped in the
// {"policies":…} envelope that OPA expects when reading bundle files.
func (p *PolicyPuller) persistPolicies(normalized map[string]any) error {
	root := map[string]any{"policies": normalized}
	content, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return err
	}
	return atomicfile.WriteFile(p.cfg.PolicyFile, append(content, '\n'))
}

// persistPIPs writes the normalised PIP document to disk in OPA data-directory
// format: {"pips": <NormalizedPIPs>}.  The "pips" wrapper key makes OPA produce
// data.pips on startup load, matching the /v1/data/pips document root that
// pushPIPsToOPA targets.  Keeping the disk and push representations identical is
// the invariant guarded by opa_document_roots_test.go.
func (p *PolicyPuller) persistPIPs(doc *pips.PIPDocument) error {
	opaDoc := map[string]any{"pips": doc.Normalized}
	content, err := json.MarshalIndent(opaDoc, "", "  ")
	if err != nil {
		return err
	}
	return atomicfile.WriteFile(p.cfg.PIPFile, append(content, '\n'))
}

// pushPoliciesToOPA sends the normalised policy map to OPA's data API.
// The map is PUT to the URL that maps to data.policies inside OPA (without the
// {"policies":…} wrapper — the URL path encodes the data document key).
func (p *PolicyPuller) pushPoliciesToOPA(ctx context.Context, policies map[string]any) error {
	if p.cfg.OPAPoliciesURL == "" {
		return nil
	}
	body, err := json.Marshal(policies)
	if err != nil {
		return err
	}
	return p.opaRequest(ctx, http.MethodPut, p.cfg.OPAPoliciesURL, body)
}

// pushPIPsToOPA sends the normalised PIP document to OPA's data API.
func (p *PolicyPuller) pushPIPsToOPA(ctx context.Context, normalized *pips.NormalizedPIPs) error {
	if p.cfg.OPAPIPsURL == "" {
		return nil
	}
	body, err := json.Marshal(normalized)
	if err != nil {
		return err
	}
	return p.opaRequest(ctx, http.MethodPut, p.cfg.OPAPIPsURL, body)
}

func (p *PolicyPuller) opaRequest(ctx context.Context, method, url string, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.opaClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("OPA %s %s: HTTP %d", method, url, resp.StatusCode)
	}
	return nil
}
