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

package pips

import (
	"os"
	"strconv"
	"strings"
)

// Environment variables consumed at pap-client startup to materialise
// the container-pinned entitlements PIP entry per ADR-0054 + D-AG-17.
// The variable names mirror the existing `AUTHZ_JWKS_HTTP_*` block so the
// knob shape is consistent for operators.
const (
	EnvEntitlementsURL         = "AUTHZ_ENTITLEMENTS_URL"
	EnvEntitlementsHTTPTimeout = "AUTHZ_ENTITLEMENTS_HTTP_TIMEOUT"
	EnvEntitlementsHTTPRetries = "AUTHZ_ENTITLEMENTS_HTTP_RETRIES"
)

// LoadEntitlementsConfigFromEnv reads the three AUTHZ_ENTITLEMENTS_*
// environment variables and returns a populated config, or nil when
// AUTHZ_ENTITLEMENTS_URL is unset. Trailing slashes on the URL are
// stripped so the rego resolver can always compose
// `${URL}/api/v3/user-entitlements/user/{userId}` without worrying
// about double-`/`.
//
// Unparseable numeric values for timeout/retries fall back to the
// defaults (mirroring DefaultJWKSHTTPTimeout / DefaultJWKSHTTPRetries
// defaults) so a misconfigured env block produces a structured
// warning rather than a crash. A zero or negative parsed value also
// falls back to the default.
func LoadEntitlementsConfigFromEnv() *EntitlementsConfig {
	url := strings.TrimSpace(os.Getenv(EnvEntitlementsURL))
	if url == "" {
		return nil
	}
	url = strings.TrimRight(url, "/")
	return &EntitlementsConfig{
		URL:                url,
		HTTPTimeoutSeconds: envIntOrDefault(EnvEntitlementsHTTPTimeout, DefaultEntitlementsHTTPTimeout),
		HTTPRetries:        envIntOrDefault(EnvEntitlementsHTTPRetries, DefaultEntitlementsHTTPRetries),
	}
}

func envIntOrDefault(key string, fallback int) int {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(raw)
	if err != nil || parsed <= 0 {
		return fallback
	}
	return parsed
}

// ApplyEntitlementsOverride merges the container-pinned entitlements
// entry into a normalized PIP document produced by Normalize /
// NormalizeItems. It is idempotent: calling it twice with the same
// config leaves the document unchanged. Passing a nil config is a
// no-op — the document round-trips without an `entitlements` block,
// and the rego resolver's `data.pips.remote.entitlements` absence
// check short-circuits the ENT resolution path.
//
// The merge touches four index positions:
//
//  1. `Normalized.ByName[EntitlementsPIPName]` — so
//     `known_pip_aliases` classifies `entitledResources` as a known PIP
//     in deny-reason enrichment.
//  2. `Normalized.AliasSet[EntitlementsPIPAlias] = true` — same
//     reason; kept in sync with ByName so constant-time alias lookups
//     succeed.
//  3. `Normalized.Remote.Entitlements` — the authoritative entry rego
//     reads at evaluation time.
//  4. (Raw items are unchanged — the container-pinned entry is not part
//     of the upload contract per ADR-0037.)
func ApplyEntitlementsOverride(doc *PIPDocument, cfg *EntitlementsConfig) {
	if doc == nil {
		return
	}
	entry := cfg.Entry()
	if entry == nil {
		// Explicit absence: clear any stale ENTITLEMENT material that
		// may have been persisted from a prior config. This keeps the
		// on-disk document deterministic: the only source of truth
		// for the entitlements entry is the live env block.
		delete(doc.Normalized.ByName, EntitlementsPIPName)
		delete(doc.Normalized.AliasSet, EntitlementsPIPAlias)
		doc.Normalized.Remote.Entitlements = nil
		return
	}
	if doc.Normalized.ByName == nil {
		doc.Normalized.ByName = make(map[string]NormalizedEntry)
	}
	if doc.Normalized.AliasSet == nil {
		doc.Normalized.AliasSet = make(map[string]bool)
	}
	doc.Normalized.ByName[EntitlementsPIPName] = NormalizedEntry{
		Name:    entry.Name,
		Alias:   entry.Alias,
		PipType: PipTypeEntitlements,
	}
	doc.Normalized.AliasSet[entry.Alias] = true
	doc.Normalized.Remote.Entitlements = entry
}

// EmptyDocumentWithEntitlements returns a minimal PIPDocument that
// carries only the container-pinned entitlements entry. Used on
// pap-client startup when AUTHZ_ENTITLEMENTS_URL is set but no
// user-uploaded PIP document exists yet, so the rego resolver can
// materialise entitlements even on a fresh container.
func EmptyDocumentWithEntitlements(cfg *EntitlementsConfig) *PIPDocument {
	doc := &PIPDocument{
		Raw: RawPIPDocument{Version: 1, Items: []SimplifiedPIP{}},
		Normalized: NormalizedPIPs{
			ByName:   make(map[string]NormalizedEntry),
			AliasSet: make(map[string]bool),
			Local: LocalPIPs{
				Token:  make(map[string]TokenPIPConfig),
				Header: make(map[string]HeaderPIPConfig),
			},
			Remote: RemotePIPs{
				General: make(map[string]GeneralPIPConfig),
			},
			Activation: ActivationIndexes{
				GeneralByResourceTypeOperation: make(map[string]map[string][]string),
			},
		},
	}
	ApplyEntitlementsOverride(doc, cfg)
	return doc
}
