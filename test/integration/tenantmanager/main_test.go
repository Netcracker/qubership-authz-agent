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

package main

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func TestParseTenants_Accepted(t *testing.T) {
	tests := []struct {
		name string
		spec string
		want map[string]string
	}{
		{"one pair", "default=id-a", map[string]string{"default": "id-a"}},
		{"spaces and an empty item are dropped", " default = id-a , ,cpq=id-b", map[string]string{"default": "id-a", "cpq": "id-b"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseTenants(tt.spec)
			if err != nil {
				t.Fatalf("parseTenants(%q) error = %v, want none", tt.spec, err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseTenants(%q) = %v, want %v", tt.spec, got, tt.want)
			}
		})
	}
}

func TestParseTenants_Rejected(t *testing.T) {
	tests := []struct {
		name string
		spec string
	}{
		{"empty list", ""},
		{"only separators", " , "},
		{"no equals sign", "default"},
		{"empty name", "=id-a"},
		{"empty identifier", "default="},
		{"name listed twice", "default=id-a,default=id-b"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, err := parseTenants(tt.spec); err == nil {
				t.Errorf("parseTenants(%q) = %v, want an error", tt.spec, got)
			}
		})
	}
}

// The registered name gets its identifier as the whole body, the format
// tenant-manager returns it in.
func TestLookup_RegisteredNameReturnsItsIdentifier(t *testing.T) {
	handler := newHandler(map[string]string{"default": "6f1c2a9e-3b4d-4e8f-9a1b-2c3d4e5f6a7b"})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, lookupPath+"?dns=default", nil))

	if rec.Code != http.StatusOK {
		t.Errorf("GET ?dns=default status = %d, want %d", rec.Code, http.StatusOK)
	}
	if got := rec.Body.String(); got != "6f1c2a9e-3b4d-4e8f-9a1b-2c3d4e5f6a7b" {
		t.Errorf("GET ?dns=default body = %q, want %q", got, "6f1c2a9e-3b4d-4e8f-9a1b-2c3d4e5f6a7b")
	}
	if got := rec.Header().Get("Content-Type"); got != "text/plain; charset=utf-8" {
		t.Errorf("GET ?dns=default Content-Type = %q, want %q", got, "text/plain; charset=utf-8")
	}
}

func TestHandler_Status(t *testing.T) {
	handler := newHandler(map[string]string{"default": "6f1c2a9e-3b4d-4e8f-9a1b-2c3d4e5f6a7b"})
	tests := []struct {
		name   string
		method string
		target string
		want   int
	}{
		{"unregistered name", http.MethodGet, lookupPath + "?dns=cpq", http.StatusNotFound},
		{"name in another case", http.MethodGet, lookupPath + "?dns=Default", http.StatusNotFound},
		{"no dns parameter", http.MethodGet, lookupPath, http.StatusBadRequest},
		{"empty dns parameter", http.MethodGet, lookupPath + "?dns=", http.StatusBadRequest},
		{"method other than GET", http.MethodPost, lookupPath + "?dns=default", http.StatusMethodNotAllowed},
		{"another tenant-manager path", http.MethodGet, "/api/v4/tenant-manager/manage/tenants", http.StatusNotFound},
		{"health", http.MethodGet, "/health", http.StatusOK},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(tt.method, tt.target, nil))
			if rec.Code != tt.want {
				t.Errorf("%s %s status = %d, want %d", tt.method, tt.target, rec.Code, tt.want)
			}
		})
	}
}
