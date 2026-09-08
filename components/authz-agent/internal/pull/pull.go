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

// Package pull keeps data.policies and data.pips, the documents the
// decision policies read, in step with their source: the v3 configuration
// API of the policy source, fetched every interval and converted to the
// simplified model, or a mounted directory that carries the simplified
// model itself. [Puller.Status] reports the first successful load, which
// readiness waits for, and the counts of the last conversion.
package pull

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/open-policy-agent/opa/v1/util"

	"authz-agent/internal/acconfig"
	"authz-agent/internal/pips"
	"authz-agent/internal/simplifiedpolicies"
)

// Defaults of Config.
const (
	DefaultInterval    = 30 * time.Second
	DefaultHTTPTimeout = 30 * time.Second
	DefaultMountDir    = "/etc/authz/policies"
	// tokenWait bounds how long the first pull waits for the m2m token.
	tokenWait = 15 * time.Second
	// MountPoliciesFile and MountPIPsFile are the files of the mount
	// directory: JSON arrays of simplified policies and PIPs.
	MountPoliciesFile = "policies.json"
	MountPIPsFile     = "pips.json"
)

// Config selects the source. MountDir, when it exists, wins over
// SourceURL. A zero Interval disables the pull and the mount alike, and so
// does an empty SourceURL without a mount; the status then reports the
// policies as loaded, so that readiness does not wait for a load that
// never comes.
type Config struct {
	// SourceURL is the base URL of the policy source, whose
	// /access/v3/config/policySets and /access/v3/config/pips are fetched.
	SourceURL string
	// Interval is the pull period, and the poll period of the mount.
	Interval time.Duration
	// MountDir is the directory that carries policies.json and pips.json.
	MountDir string
	// HTTPTimeout bounds one fetch from the source.
	HTTPTimeout time.Duration
	// Entitlements is the entitlements PIP pinned by the deployment; nil
	// adds none.
	Entitlements *pips.EntitlementsConfig
}

// Store receives the documents.
type Store interface {
	Put(ctx context.Context, path []string, value any) error
}

// Tokens supplies the bearer token the source is fetched with; nil fetches
// without one.
type Tokens interface {
	Token() string
	Ready() <-chan struct{}
}

// Logger receives the diagnostics.
type Logger interface {
	Infof(format string, args ...any)
	Warnf(format string, args ...any)
}

// Conversion counts what the last conversion of the source's policy sets
// produced. A pull that fetched every policy set and converted none is a
// successful pull by every other measure, and it is what an authorization
// outage looks like from outside.
type Conversion struct {
	PolicySets        int `json:"policySets"`
	PolicySetsSkipped int `json:"policySetsSkipped"`
	Rules             int `json:"rules"`
	RulesSkipped      int `json:"rulesSkipped"`
	RulesDenySkipped  int `json:"rulesDenySkipped"`
	Policies          int `json:"policies"`
}

// Status reports the pull. PoliciesLoaded is set by the first successful
// load and never cleared: a source that becomes unreachable leaves the
// documents already in the store, which are better than none. Reason
// explains a PoliciesLoaded set without a load because the pull is
// disabled.
type Status struct {
	PoliciesLoaded bool        `json:"policiesLoaded"`
	FirstSuccessAt string      `json:"firstSuccessAt,omitempty"`
	LastSuccessAt  string      `json:"lastSuccessAt,omitempty"`
	Reason         string      `json:"reason,omitempty"`
	Conversion     *Conversion `json:"conversion,omitempty"`
}

// Puller loads the documents into one store.
type Puller struct {
	cfg    Config
	store  Store
	tokens Tokens
	log    Logger
	client *http.Client
	// stdlog adapts the diagnostics for the converter, which logs through
	// the standard library.
	stdlog *log.Logger

	mu             sync.Mutex
	status         Status
	firstSuccess   time.Time
	lastConversion *Conversion
	appliedHashes  [2]string
}

// New returns a puller for cfg; an HTTPTimeout that is zero or negative
// and a negative Interval take the defaults.
func New(cfg Config, store Store, tokens Tokens, logger Logger) *Puller {
	if cfg.Interval < 0 {
		cfg.Interval = DefaultInterval
	}
	if cfg.HTTPTimeout <= 0 {
		cfg.HTTPTimeout = DefaultHTTPTimeout
	}
	return &Puller{
		cfg:    cfg,
		store:  store,
		tokens: tokens,
		log:    logger,
		client: &http.Client{Timeout: cfg.HTTPTimeout},
		stdlog: log.New(writerFunc(func(p []byte) { logger.Warnf("policies: %s", strings.TrimSpace(string(p))) }), "", 0),
	}
}

// Status is the state of the pull.
func (p *Puller) Status() Status {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.status
}

// Run loads the documents until ctx ends: from the mount directory when
// it exists, else from the source every interval, starting with an
// immediate load. A failed load keeps the previous documents and is retried
// on the next tick.
func (p *Puller) Run(ctx context.Context) {
	if p.mounted() {
		p.runMount(ctx)
		return
	}
	if strings.TrimSpace(p.cfg.SourceURL) == "" {
		p.log.Infof("policies: pull disabled, no source URL")
		p.disabled("pull disabled: source URL empty")
		return
	}
	if p.cfg.Interval == 0 {
		p.log.Infof("policies: pull disabled, interval is 0")
		p.disabled("pull disabled: interval is 0")
		return
	}
	p.log.Infof("policies: pulling from %s every %s", p.cfg.SourceURL, p.cfg.Interval)
	p.waitForToken(ctx)
	p.pull(ctx)
	ticker := time.NewTicker(p.cfg.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.pull(ctx)
		}
	}
}

func (p *Puller) pull(ctx context.Context) {
	if err := p.PullOnce(ctx); err != nil {
		p.log.Warnf("policies: pull failed, keeping the previous documents: %v", err)
		return
	}
	p.loaded()
}

// waitForToken gives the token source a bounded time to obtain the first
// token, so the first pull is not a foreseeable 401.
func (p *Puller) waitForToken(ctx context.Context) {
	if p.tokens == nil {
		return
	}
	select {
	case <-p.tokens.Ready():
	case <-ctx.Done():
	case <-time.After(tokenWait):
		p.log.Warnf("policies: no m2m token after %s, pulling without one", tokenWait)
	}
}

func (p *Puller) mounted() bool {
	if p.cfg.MountDir == "" {
		return false
	}
	info, err := os.Stat(p.cfg.MountDir)
	return err == nil && info.IsDir()
}

func (p *Puller) runMount(ctx context.Context) {
	if p.cfg.Interval == 0 {
		p.log.Infof("policies: mount %s, watch disabled", p.cfg.MountDir)
		p.disabled("mount watcher disabled: interval is 0")
		return
	}
	p.log.Infof("policies: loading from mount %s every %s", p.cfg.MountDir, p.cfg.Interval)
	p.applyMount(ctx)
	ticker := time.NewTicker(p.cfg.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.applyMount(ctx)
		}
	}
}

func (p *Puller) applyMount(ctx context.Context) {
	changed, err := p.ApplyMount(ctx)
	switch {
	case err != nil:
		p.log.Warnf("policies: mount reload failed, keeping the previous documents: %v", err)
	case changed:
		p.log.Infof("policies: loaded from mount %s", p.cfg.MountDir)
		p.loaded()
	}
}

// PullOnce fetches the policy sets and the PIPs from the source and loads
// them; the documents in the store are untouched when any step fails.
func (p *Puller) PullOnce(ctx context.Context) error {
	token := ""
	if p.tokens != nil {
		token = p.tokens.Token()
	}
	policySets, err := p.fetch(ctx, p.cfg.SourceURL+"/access/v3/config/policySets", token)
	if err != nil {
		return fmt.Errorf("fetch policySets: %w", err)
	}
	pipsRaw, err := p.fetch(ctx, p.cfg.SourceURL+"/access/v3/config/pips", token)
	if err != nil {
		return fmt.Errorf("fetch pips: %w", err)
	}
	policyList, stats, err := acconfig.ConvertPolicySets(policySets, p.stdlog)
	if err != nil {
		return fmt.Errorf("convert policySets: %w", err)
	}
	conversion := Conversion(stats)
	if stats.RulesSkipped > 0 || stats.PolicySetsSkipped > 0 {
		p.log.Warnf("policies: conversion dropped data: %d/%d policy sets and %d/%d rules could not be converted (%d policies produced)",
			stats.PolicySetsSkipped, stats.PolicySets, stats.RulesSkipped, stats.Rules, stats.Policies)
	}
	pipList, err := acconfig.ConvertPIPs(pipsRaw, p.stdlog)
	if err != nil {
		return fmt.Errorf("convert pips: %w", err)
	}
	policies, err := simplifiedpolicies.NormalizePolicies(policyList)
	if err != nil {
		return fmt.Errorf("normalize policies: %w", err)
	}
	pipDoc, _, err := pips.NormalizeItems(pipList)
	if err != nil {
		return fmt.Errorf("normalize pips: %w", err)
	}
	if err := p.load(ctx, policies, pipDoc); err != nil {
		return err
	}
	p.mu.Lock()
	p.lastConversion = &conversion
	p.mu.Unlock()
	p.log.Infof("policies: updated (%d policies, %d PIPs)", stats.Policies, len(pipList))
	return nil
}

// ApplyMount loads the mount's files when either changed since the last
// load. It returns true when the documents were replaced.
func (p *Puller) ApplyMount(ctx context.Context) (bool, error) {
	policiesFile := filepath.Join(p.cfg.MountDir, MountPoliciesFile)
	pipsFile := filepath.Join(p.cfg.MountDir, MountPIPsFile)
	policiesRaw, policiesHash, err := readHashed(policiesFile)
	if err != nil {
		return false, err
	}
	pipsRaw, pipsHash, err := readHashed(pipsFile)
	if err != nil {
		return false, err
	}
	p.mu.Lock()
	unchanged := p.appliedHashes == [2]string{policiesHash, pipsHash}
	p.mu.Unlock()
	if unchanged {
		return false, nil
	}
	policies, err := simplifiedpolicies.Normalize(policiesRaw)
	if err != nil {
		return false, fmt.Errorf("normalize policies from mount: %w", err)
	}
	pipDoc, _, err := pips.Normalize(pipsRaw)
	if err != nil {
		return false, fmt.Errorf("normalize pips from mount: %w", err)
	}
	if err := p.load(ctx, policies, pipDoc); err != nil {
		return false, err
	}
	p.mu.Lock()
	p.appliedHashes = [2]string{policiesHash, pipsHash}
	p.mu.Unlock()
	return true, nil
}

// load completes the PIP document with the pinned entitlements and the
// activation index of the general PIPs, then stores both documents as the
// data API received them.
func (p *Puller) load(ctx context.Context, policies map[string]any, pipDoc *pips.PIPDocument) error {
	pips.ApplyEntitlementsOverride(pipDoc, p.cfg.Entitlements)
	pipDoc.Normalized.Activation.GeneralByResourceTypeOperation = pips.BuildActivationIndexFromPolicies(pipDoc.Normalized.Remote.General, policies)
	policiesDoc, err := roundTrip(policies)
	if err != nil {
		return fmt.Errorf("encode policies: %w", err)
	}
	pipsDoc, err := roundTrip(pipDoc.Normalized)
	if err != nil {
		return fmt.Errorf("encode pips: %w", err)
	}
	if err := p.store.Put(ctx, []string{"policies"}, policiesDoc); err != nil {
		return fmt.Errorf("store policies: %w", err)
	}
	if err := p.store.Put(ctx, []string{"pips"}, pipsDoc); err != nil {
		return fmt.Errorf("store pips: %w", err)
	}
	return nil
}

func (p *Puller) fetch(ctx context.Context, url, token string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return nil, fmt.Errorf("read response from %s: %w", url, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("%s: HTTP %d: %s", url, resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	return raw, nil
}

func (p *Puller) loaded() {
	now := time.Now().UTC()
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.firstSuccess.IsZero() {
		p.firstSuccess = now
	}
	p.status = Status{
		PoliciesLoaded: true,
		FirstSuccessAt: p.firstSuccess.Format(time.RFC3339),
		LastSuccessAt:  now.Format(time.RFC3339),
		Conversion:     p.lastConversion,
	}
}

func (p *Puller) disabled(reason string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.status = Status{PoliciesLoaded: true, Reason: reason}
}

// roundTrip converts a Go value to the JSON values the store holds, with
// numbers as json.Number, as the data API decoded its request bodies.
func roundTrip(v any) (any, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var out any
	if err := util.UnmarshalJSON(raw, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func readHashed(path string) ([]byte, string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, "", fmt.Errorf("read %s: %w", path, err)
	}
	sum := sha256.Sum256(raw)
	return raw, hex.EncodeToString(sum[:]), nil
}

type writerFunc func(p []byte)

func (w writerFunc) Write(p []byte) (int, error) {
	w(p)
	return len(p), nil
}
