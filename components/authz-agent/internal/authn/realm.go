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

package authn

import (
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// tenantLookupPath resolves one of a tenant's names to its identifier. The
// endpoint answers with the identifier as a bare text body and needs no
// credentials.
const tenantLookupPath = "/api/v4/tenant-manager/registration/tenants"

// realmSegment is the accepted shape of a realm name, applied to the name
// sent and to the identifier received: it becomes a URL path segment of a
// discovery request, and tenant-manager's answer is input.
var realmSegment = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

// realmResolver turns a realm display name into the realm name Keycloak
// serves under. A tenant realm is created with a generated UUID as its name
// and keeps the readable name only as its display name, so a configured
// issuer that ends in the display name is not addressable until resolved.
// A nil resolver resolves nothing.
type realmResolver struct {
	baseURL string
	client  *http.Client
	log     Logger
	// cache keeps one answer per name for the life of the process; a
	// negative answer is cached too, so an unknown name is asked once.
	cache map[string]string
}

func newRealmResolver(baseURL string, client *http.Client, log Logger) *realmResolver {
	trimmed := strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if trimmed == "" {
		return nil
	}
	return &realmResolver{baseURL: trimmed, client: client, log: log, cache: map[string]string{}}
}

// resolveIssuer rewrites the last path segment of issuer when it is a
// tenant display name; scheme, host, and the rest of the path stay as
// configured. ok is false when nothing was rewritten.
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
	if !realmSegment.MatchString(segment) {
		return issuer, false
	}
	resolved, ok := r.resolve(segment)
	if !ok {
		return issuer, false
	}
	return prefix + "/" + resolved, true
}

// resolve maps a display name to a realm name; ok is false when the name
// is not a known tenant, tenant-manager is unreachable, or the answer is
// not a realm name, so a resolver that cannot answer never breaks a
// bootstrap that would otherwise work.
func (r *realmResolver) resolve(displayName string) (string, bool) {
	if r == nil || displayName == "" {
		return "", false
	}
	if cached, ok := r.cache[displayName]; ok {
		return cached, cached != ""
	}
	resolved, ok := r.lookup(displayName)
	if !ok {
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
		r.log.Infof("trusted providers: realm %q not resolved via tenant-manager (%v); using it as the realm name", displayName, err)
		return "", false
	}
	resolved := strings.TrimSpace(string(body))
	if resolved == "" {
		return "", false
	}
	if !realmSegment.MatchString(resolved) {
		r.log.Warnf("trusted providers: tenant-manager answered %q for realm %q, which is not a usable realm name; ignoring", truncate(resolved), displayName)
		return "", false
	}
	if resolved == displayName {
		return "", false
	}
	r.log.Infof("trusted providers: realm %q resolved to %q via tenant-manager", displayName, resolved)
	return resolved, true
}

func truncate(s string) string {
	const limit = 80
	if len(s) <= limit {
		return s
	}
	return s[:limit] + "..."
}
