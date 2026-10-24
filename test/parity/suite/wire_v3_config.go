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
)

// HelperGetConfigExport reads one of the v3 configuration export endpoints
// (Meta(id).PathTmpl) with the M2M token and returns the status and the raw
// body. The tenant query parameter and the Tenant header follow opts the way
// the decision helpers apply them.
func HelperGetConfigExport(ctx context.Context, cfg Config, id ParityEndpointID, m2mToken string, opts PerCallOptions) (int, []byte, error) {
	endpoint := buildURL(cfg.ACBaseURL, Meta(id).PathTmpl, buildQuery(cfg, opts, nil))
	req, err := buildRequest(ctx, http.MethodGet, endpoint, nil, TokenBundle{M2M: m2mToken}, opts)
	if err != nil {
		return 0, nil, err
	}
	return doRequest(req)
}
