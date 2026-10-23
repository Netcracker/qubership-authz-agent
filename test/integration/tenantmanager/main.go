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

// Command tenant-manager emulates the one tenant-manager request the agent
// sends: GET /api/v4/tenant-manager/registration/tenants?dns=<name>, which
// turns a tenant's name into the identifier its Keycloak realm is named by.
// The response is the identifier as a plain-text body, or 404 for a name the
// emulator does not know; names match case-sensitively. A request without
// dns gets 400, and a method other than GET gets 405.
//
// The tenants come from TENANT_MANAGER_TENANTS, a comma-separated list of
// name=identifier pairs, read once at start; an invalid list stops the
// process before it listens:
//
//	TENANT_MANAGER_TENANTS=default=6f1c2a9e-3b4d-4e8f-9a1b-2c3d4e5f6a7b
//
// TENANT_MANAGER_PORT sets the listen port, 8080 by default. GET /health
// returns 200 for a readiness probe.
package main

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

// lookupPath is the tenant-manager endpoint the agent calls.
const lookupPath = "/api/v4/tenant-manager/registration/tenants"

// parseTenants reads the name=identifier pairs of TENANT_MANAGER_TENANTS.
// Spaces around a name or an identifier are dropped, and an empty item
// between two commas is skipped. A list with no pair, a pair without '=', an
// empty name or identifier, and a name listed twice are errors.
func parseTenants(spec string) (map[string]string, error) {
	tenants := map[string]string{}
	for _, pair := range strings.Split(spec, ",") {
		if strings.TrimSpace(pair) == "" {
			continue
		}
		name, id, ok := strings.Cut(pair, "=")
		name, id = strings.TrimSpace(name), strings.TrimSpace(id)
		switch {
		case !ok:
			return nil, fmt.Errorf("tenant %q has no '=' between the name and the identifier", pair)
		case name == "":
			return nil, fmt.Errorf("tenant %q has an empty name", pair)
		case id == "":
			return nil, fmt.Errorf("tenant %q has an empty identifier", pair)
		}
		if _, dup := tenants[name]; dup {
			return nil, fmt.Errorf("tenant name %q is listed twice", name)
		}
		tenants[name] = id
	}
	if len(tenants) == 0 {
		return nil, errors.New("no tenant listed")
	}
	return tenants, nil
}

// newHandler serves the lookup for tenants and /health; every other path is
// 404.
func newHandler(tenants map[string]string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(lookupPath, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		name := r.URL.Query().Get("dns")
		if name == "" {
			http.Error(w, "the dns query parameter is missing", http.StatusBadRequest)
			return
		}
		id, ok := tenants[name]
		if !ok {
			log.Printf("lookup %q: not registered", name)
			http.Error(w, "tenant not registered", http.StatusNotFound)
			return
		}
		log.Printf("lookup %q: %s", name, id)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte(id))
	})
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	return mux
}

func main() {
	tenants, err := parseTenants(os.Getenv("TENANT_MANAGER_TENANTS"))
	if err != nil {
		log.Fatalf("TENANT_MANAGER_TENANTS: %v", err)
	}
	port := os.Getenv("TENANT_MANAGER_PORT")
	if port == "" {
		port = "8080"
	}
	for name, id := range tenants {
		log.Printf("tenant %q is %s", name, id)
	}
	server := &http.Server{
		Addr:              ":" + port,
		Handler:           newHandler(tenants),
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Printf("tenant-manager emulator listening on :%s", port)
	log.Fatal(server.ListenAndServe())
}
