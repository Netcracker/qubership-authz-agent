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

package keys

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// tenantLookupPath is the tenant-manager endpoint that returns the realm
// identifier of the tenant its dns query parameter names, as a plain-text
// body. It needs no credentials.
const tenantLookupPath = "/api/v4/tenant-manager/registration/tenants"

// maxTenantResponseBytes bounds the body of a tenant-manager answer, which is
// one realm identifier.
const maxTenantResponseBytes = 1024

// realmSegment is the accepted shape of a tenant name and of a realm
// identifier, which realmSegmentRule states for messages. The name goes into
// the dns query parameter, and the identifier, input from tenant-manager,
// takes its place as a path segment of the discovery request.
var realmSegment = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

// realmSegmentRule is the rule of validRealmSegment, worded for an error.
const realmSegmentRule = `1 to 128 letters, digits, '.', '_', and '-', other than "." and ".."`

// validRealmSegment reports whether s may stand as the realm segment of an
// issuer: it matches realmSegment and is neither "." nor "..", which would
// move the discovery request to another path of the provider.
func validRealmSegment(s string) bool {
	return realmSegment.MatchString(s) && s != "." && s != ".."
}

// tenantName returns the last segment of the escaped path of issuer, a
// trailing slash ignored, and whether it is a valid realm segment; a segment
// with an escaped character is not.
func tenantName(issuer string) (string, bool) {
	u, err := url.Parse(issuer)
	if err != nil {
		return "", false
	}
	path := strings.TrimRight(u.EscapedPath(), "/")
	name := path[strings.LastIndex(path, "/")+1:]
	return name, validRealmSegment(name)
}

// realmIssuer returns issuer with realm in place of its last path segment;
// the scheme, the host, the escaped rest of the path, the query, and the
// fragment stay as configured, and a trailing slash is dropped. issuer passed
// [Provider] validation, so tenantName accepts it.
func realmIssuer(issuer, realm string) string {
	u, _ := url.Parse(issuer)
	path := strings.TrimRight(u.EscapedPath(), "/")
	escaped := path[:strings.LastIndex(path, "/")+1] + realm
	u.Path, _ = url.PathUnescape(escaped)
	u.RawPath = escaped
	return u.String()
}

// tenantResolver queries tenant-manager for the realm identifier of a tenant.
type tenantResolver struct {
	baseURL string
	client  *http.Client
}

// newTenantResolver builds the client for tenant-manager at baseURL: the
// proxy settings of the environment, timeout per request, the system roots,
// and no redirect followed, so the answer comes from the configured address.
func newTenantResolver(baseURL string, timeout time.Duration) *tenantResolver {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	return &tenantResolver{
		baseURL: strings.TrimRight(baseURL, "/"),
		client:  noRedirectClient(transport, timeout),
	}
}

// realm returns the realm identifier tenant-manager returns for the tenant
// name. It fails when the request fails or gets a status other than 2xx, a
// redirect included, when the body is longer than maxTenantResponseBytes,
// and when the body, white space around it trimmed, is not a valid realm
// segment.
func (r *tenantResolver) realm(ctx context.Context, name string) (string, error) {
	endpoint := r.baseURL + tenantLookupPath + "?dns=" + url.QueryEscape(name)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "text/plain")
	resp, err := r.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("tenant-manager: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxTenantResponseBytes+1))
	if err != nil {
		return "", fmt.Errorf("tenant-manager GET %s: read body: %w", endpoint, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return "", fmt.Errorf("tenant-manager GET %s: HTTP %d", endpoint, resp.StatusCode)
	}
	if len(body) > maxTenantResponseBytes {
		return "", fmt.Errorf("tenant-manager GET %s: response is longer than %d bytes", endpoint, maxTenantResponseBytes)
	}
	realm := strings.TrimSpace(string(body))
	if !validRealmSegment(realm) {
		return "", fmt.Errorf("tenant-manager GET %s: %q is not a realm identifier of %s", endpoint, truncate(realm, 80), realmSegmentRule)
	}
	return realm, nil
}

// truncate shortens s to at most limit bytes for a message, marking the cut.
func truncate(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	return s[:limit] + "..."
}
