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

package snapshot

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

// The collector counts the tenants of the last load by the snapshot they
// answer from: a tenant whose latest candidate is published is current, one
// whose refused candidate leaves an earlier snapshot in place is stale, and
// one refused on its first load has none.
func TestTheCollectorCountsTenantsBySnapshot(t *testing.T) {
	r := New(Config{}, tab(t), quiet{})
	load(t, r, ``, set("a", "true"), set("b", "true"))
	load(t, r, ``, set("a", broken), set("b", "true"), set("c", broken))

	const want = `
# HELP authz_agent_policy_tenants Tenants of the last policy load by the snapshot they answer from: current (the latest candidate), stale (an earlier snapshot, because the latest candidate was refused), or none (every candidate was refused, so the tenant denies every request).
# TYPE authz_agent_policy_tenants gauge
authz_agent_policy_tenants{snapshot="current"} 1
authz_agent_policy_tenants{snapshot="none"} 1
authz_agent_policy_tenants{snapshot="stale"} 1
`
	if err := testutil.CollectAndCompare(NewCollector(r), strings.NewReader(want)); err != nil {
		t.Error(err)
	}
}
