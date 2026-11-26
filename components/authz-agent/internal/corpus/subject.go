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

// Package corpus reads a request of the specification's corpus bundles as
// the service reads the HTTP request it stands for.
package corpus

import (
	"encoding/json"
	"fmt"
	"strings"

	"authz-agent/components/authz-agent/internal/snapshot"
)

// Subject is the [snapshot.Subject] of a recorded request in tenant, built
// by [snapshot.NewSubject] from the headers the request recorded and from
// claims, the verified claims of its subject, which the server receives as
// the admission's token payload. claims is JSON text, nil for none.
//
// anonymous is whether the specification decided the request as
// anonymous. Subject returns an error where the service reads the headers
// the other way, since the replay would then decide on another subject than
// the specification did: a request recorded as not anonymous in a bundle
// that leaves out the token headers, or a request whose subject the two read
// differently.
func Subject(tenant string, headers map[string]string, claims *string, anonymous bool) (snapshot.Subject, error) {
	h := make(map[string][]string, len(headers))
	for k, v := range headers {
		h[k] = []string{v}
	}
	var payload any
	if claims != nil {
		d := json.NewDecoder(strings.NewReader(*claims))
		d.UseNumber()
		if err := d.Decode(&payload); err != nil {
			return snapshot.Subject{}, fmt.Errorf("claims: %w", err)
		}
	}
	sub, err := snapshot.NewSubject(tenant, h, payload)
	if err != nil {
		return sub, err
	}
	if sub.Anonymous != anonymous {
		return sub, fmt.Errorf("the service reads the headers as anonymous=%v, the specification recorded anonymous=%v",
			sub.Anonymous, anonymous)
	}
	return sub, nil
}
