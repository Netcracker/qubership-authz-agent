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

import "github.com/prometheus/client_golang/prometheus"

// tenantsDesc answers whether a refused policy change leaves a tenant on an
// earlier snapshot, or on none: the tenant then allows what its latest
// policies revoke, and a replica that restarts meanwhile has no snapshot of
// it and denies what its siblings allow. Its warning names the tenant; the
// gauge counts them for an alert.
var tenantsDesc = prometheus.NewDesc("authz_agent_policy_tenants",
	"Tenants of the last policy load by the snapshot they answer from: current (the latest candidate), "+
		"stale (an earlier snapshot, because the latest candidate was refused), or none (every candidate was "+
		"refused, so the tenant denies every request).",
	[]string{"snapshot"}, nil)

// Collector exports the gauge authz_agent_policy_tenants of a [Registry].
type Collector struct {
	r *Registry
}

// NewCollector returns the collector of r, for a Prometheus registry.
func NewCollector(r *Registry) *Collector { return &Collector{r: r} }

// Describe implements [prometheus.Collector].
func (c *Collector) Describe(ch chan<- *prometheus.Desc) { ch <- tenantsDesc }

// Collect implements [prometheus.Collector].
func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	counts := map[string]float64{"current": 0, "stale": 0, "none": 0}
	for _, th := range c.r.cur.Load().tenants {
		switch {
		case !th.Ready:
			counts["none"]++
		case th.Rejected != nil:
			counts["stale"]++
		default:
			counts["current"]++
		}
	}
	for state, n := range counts {
		ch <- prometheus.MustNewConstMetric(tenantsDesc, prometheus.GaugeValue, n, state)
	}
}
