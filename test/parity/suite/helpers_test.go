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
	"testing"
)

func TestBuildQuery_TenantID(t *testing.T) {
	t.Parallel()
	cfg := Config{TenantID: "configured"}
	empty := ""
	other := "other"
	cases := []struct {
		name string
		opts PerCallOptions
		want string
	}{
		{"configured tenant by default", PerCallOptions{}, "tenant_id=configured"},
		{"override replaces the configured tenant", PerCallOptions{TenantID: &other}, "tenant_id=other"},
		{"empty override sends an empty tenant_id", PerCallOptions{TenantID: &empty}, "tenant_id="},
		{"omit sends no tenant_id", PerCallOptions{OmitTenantID: true}, ""},
		{"omit wins over an override", PerCallOptions{OmitTenantID: true, TenantID: &other}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := buildQuery(cfg, tc.opts, nil); got != tc.want {
				t.Errorf("buildQuery(%+v) = %q, want %q", tc.opts, got, tc.want)
			}
		})
	}
}

// The Tenant header travels only through TenantHeader: the same name in
// CustomHeaders is stripped, as the thin client strips it.
func TestBuildRequest_TenantHeader(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		opts PerCallOptions
		want string
	}{
		{"TenantHeader is sent", PerCallOptions{TenantHeader: "tenant-b"}, "tenant-b"},
		{"custom Tenant header is stripped", PerCallOptions{CustomHeaders: map[string]string{"Tenant": "tenant-b"}}, ""},
		{"TenantHeader is sent beside a stripped custom header", PerCallOptions{
			TenantHeader:  "tenant-a",
			CustomHeaders: map[string]string{"tenant": "tenant-b"},
		}, "tenant-a"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			req, err := buildRequest(context.Background(), http.MethodPost, "http://parity.invalid/", nil, TokenBundle{}, tc.opts)
			if err != nil {
				t.Fatal(err)
			}
			if got := req.Header.Get("Tenant"); got != tc.want {
				t.Errorf("Tenant header for %+v = %q, want %q", tc.opts, got, tc.want)
			}
		})
	}
}
