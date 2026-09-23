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
	"net/http"
	"net/url"
)

// HelperImportCustomization posts customizations of policy sets to the PAP at
// level, PROJECT or CUSTOMER, in the tenant of cfg. The body is the list of
// customized sets, each naming the set, the policy, and the rule it changes by id.
func HelperImportCustomization(ctx context.Context, cfg Config, m2mToken, level string, customizations []any) (int, []byte, error) {
	endpoint := buildURL(
		cfg.ACBaseURL,
		Meta(PSUITE_IMPORT_CUSTOMIZATION).PathTmpl,
		url.Values{"tenant_id": []string{cfg.TenantID}, "level": []string{level}}.Encode(),
	)
	req, err := buildRequest(ctx, http.MethodPost, endpoint, customizations, TokenBundle{M2M: m2mToken}, PerCallOptions{})
	if err != nil {
		return 0, nil, err
	}
	return doRequest(req)
}

// HelperDeleteSetCustomization deletes the customization of the policy set
// setID at level, with every customization of its policies and rules. The PAP
// answers 204.
func HelperDeleteSetCustomization(ctx context.Context, cfg Config, m2mToken, level, setID string) (int, []byte, error) {
	endpoint := buildURL(
		cfg.ACBaseURL,
		"/access/v1/config/customization/policySet/"+url.PathEscape(setID),
		url.Values{"tenant_id": []string{cfg.TenantID}, "level": []string{level}, "recursive": []string{"true"}}.Encode(),
	)
	req, err := buildRequest(ctx, http.MethodDelete, endpoint, nil, TokenBundle{M2M: m2mToken}, PerCallOptions{})
	if err != nil {
		return 0, nil, err
	}
	return doRequest(req)
}

// HelperDeactivatePolicySet sets the status of the policy set setID to
// INACTIVE. An inactive set decides nothing and is left out of the v3 export.
func HelperDeactivatePolicySet(ctx context.Context, cfg Config, m2mToken, setID string) (int, []byte, error) {
	endpoint := buildURL(
		cfg.ACBaseURL,
		"/access/v1/policySets/"+url.PathEscape(setID)+"/deactivate",
		url.Values{"tenant_id": []string{cfg.TenantID}}.Encode(),
	)
	req, err := buildRequest(ctx, http.MethodPatch, endpoint, nil, TokenBundle{M2M: m2mToken}, PerCallOptions{})
	if err != nil {
		return 0, nil, err
	}
	return doRequest(req)
}

// HelperGetPAP sends a GET to path on the PAP with the suite's M2M token and the
// tenant of cfg, plus query.
func HelperGetPAP(ctx context.Context, cfg Config, m2mToken, path string, query url.Values) (int, []byte, error) {
	values := url.Values{"tenant_id": []string{cfg.TenantID}}
	for key, list := range query {
		values[key] = list
	}
	req, err := buildRequest(ctx, http.MethodGet, buildURL(cfg.ACBaseURL, path, values.Encode()), nil, TokenBundle{M2M: m2mToken}, PerCallOptions{})
	if err != nil {
		return 0, nil, err
	}
	return doRequest(req)
}
