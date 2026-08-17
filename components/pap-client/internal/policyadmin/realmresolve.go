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
	"fmt"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// DefaultTenantManagerURL is the in-namespace address of tenant-manager. Every
// platform installation runs it under this Service name.
const DefaultTenantManagerURL = "http://tenant-manager:8080"

// tenantLookupPath resolves one of a tenant's names to its identifier.
//
// The endpoint is documented as "Find tenant identifier by one of it's names"
// and answers with the identifier as a bare text body. It is UNAUTHENTICATED —
// verified from inside a Pod with no credentials of any kind — which is what
// makes it usable here. Its sibling `registration/tenants/{id}/name`, and the
// whole `manage/` surface, do require M2M and are deliberately not used.
const tenantLookupPath = "/api/v4/tenant-manager/registration/tenants"

// realmSegmentRe is the accepted shape of a realm name, applied to both the
// name we send and the identifier we get back.
//
// This is a URL path segment that goes straight into an OIDC discovery request,
// so it is validated rather than trusted: tenant-manager is a different service
// and its response is input. The set matches Keycloak's own realm-name rules and
// covers both the UUID a tenant realm gets and the plain names the platform
// realms use.
var realmSegmentRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

// realmResolver turns a realm *display* name into the realm name Keycloak
// actually serves under.
//
// Why this exists: a tenant realm is created by identity-provider with a
// generated UUID as its name, while the human-readable tenant name is kept only
// in the realm's `displayName`. So `default` — the name of the platform's
// default tenant — is not a realm anyone can address; the addressable name is a
// UUID that differs in every installation and therefore cannot be written into
// a chart. Resolving it is the only way `AUTHZ_IDP_REALMS: [default]` can mean
// what an operator expects it to mean.
type realmResolver struct {
	baseURL string
	client  *http.Client
	logger  *log.Logger

	// cache keeps one answer per name for the process lifetime. Realm names do
	// not change under a running Pod, and both the startup bootstrap and every
	// reload tick walk the same provider list.
	cache map[string]string
}

func newRealmResolver(baseURL string, client *http.Client, logger *log.Logger) *realmResolver {
	trimmed := strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if trimmed == "" {
		return nil
	}
	return &realmResolver{
		baseURL: trimmed,
		client:  client,
		logger:  logger,
		cache:   make(map[string]string),
	}
}

// resolve maps a display name to a realm name. It returns ("", false) when the
// name is not a known tenant, when tenant-manager is unreachable, or when the
// answer does not look like a realm name — every one of which means "carry on
// with the name as configured", never "fail the provider". A resolver that
// cannot answer must not be able to break a bootstrap that would otherwise work.
func (r *realmResolver) resolve(displayName string) (string, bool) {
	if r == nil || displayName == "" {
		return "", false
	}
	if cached, ok := r.cache[displayName]; ok {
		return cached, cached != ""
	}

	resolved, ok := r.lookup(displayName)
	if !ok {
		// Negative answers are cached too: a name that is not a tenant will not
		// become one while this Pod runs, and the reloader would otherwise ask
		// again on every tick.
		r.cache[displayName] = ""
		return "", false
	}

	r.cache[displayName] = resolved
	return resolved, true
}

func (r *realmResolver) lookup(displayName string) (string, bool) {
	endpoint := fmt.Sprintf("%s%s?dns=%s", r.baseURL, tenantLookupPath, url.QueryEscape(displayName))

	body, err := fetchWithRetry(r.client, endpoint, 1)
	if err != nil {
		// Includes the 404 that tenant-manager returns for a name it does not
		// know, which is the ordinary case for `cloud-common` and friends —
		// they are realms in their own right, not tenants. Debug-level noise,
		// not a warning.
		r.logger.Printf("realm %q not resolved via tenant-manager (%v); using it as the realm name", displayName, err)
		return "", false
	}

	resolved := strings.TrimSpace(string(body))
	if resolved == "" {
		return "", false
	}
	if !realmSegmentRe.MatchString(resolved) {
		r.logger.Printf("warn: tenant-manager answered %q for realm %q, which is not a usable realm name; ignoring", truncateForLog(resolved), displayName)
		return "", false
	}
	if resolved == displayName {
		return "", false
	}

	r.logger.Printf("realm %q resolved to %q via tenant-manager", displayName, resolved)
	return resolved, true
}

// resolveIssuer rewrites the realm segment of a discovery issuer when that
// segment turns out to be a tenant display name rather than a realm name.
//
// It only touches the LAST path segment and leaves scheme, host and the rest of
// the path exactly as configured — the address of the IdP stays a matter of
// configuration, and only the realm within it is looked up. Returns the original
// issuer unchanged whenever anything at all is off.
func (r *realmResolver) resolveIssuer(issuer string) (string, bool) {
	if r == nil {
		return issuer, false
	}

	trimmed := strings.TrimRight(issuer, "/")
	idx := strings.LastIndex(trimmed, "/")
	if idx < 0 || idx == len(trimmed)-1 {
		return issuer, false
	}

	prefix, segment := trimmed[:idx], trimmed[idx+1:]
	if !realmSegmentRe.MatchString(segment) {
		return issuer, false
	}

	resolved, ok := r.resolve(segment)
	if !ok {
		return issuer, false
	}

	return prefix + "/" + resolved, true
}

func truncateForLog(s string) string {
	const max = 80
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}
