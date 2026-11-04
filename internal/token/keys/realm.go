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
	"net/url"
	"strings"
	"time"
)

const (
	// realmsPath marks the iss of a Keycloak token and is the path of a realm
	// under [Keycloak.URL].
	realmsPath = "/auth/realms/"
	// realmIDPrefix starts the [Provider.ID] of a realm. Its slash keeps that
	// id apart from any id a configuration can hold.
	realmIDPrefix = "realm/"
	// maxRealmNameBytes bounds a realm name, in bytes.
	maxRealmNameBytes = 255
)

// IsRealm reports whether p stands for a realm of a [Keycloak] rather than an
// entry of [Config.Providers]. Such an entry cannot have the id of a realm,
// because [Config.Validate] refuses a slash in an id.
func (p Provider) IsRealm() bool { return strings.HasPrefix(p.ID, realmIDPrefix) }

// realmOf returns the realm that iss names: the part after the last slash of
// an iss that contains realmsPath, percent-decoded, because Keycloak encodes
// the name in an iss. The second result is false for any other iss and for a
// name [validRealm] refuses. The iss comes from a token whose signature is not
// checked yet, so the name is the sender's text.
func realmOf(iss string) (string, bool) {
	if !strings.Contains(iss, realmsPath) {
		return "", false
	}
	name, err := url.PathUnescape(iss[strings.LastIndexByte(iss, '/')+1:])
	if err != nil {
		return "", false
	}
	return name, validRealm(name)
}

// validRealm reports whether name can be a realm: one path segment of at most
// maxRealmNameBytes, and neither "." nor "..", which a server resolves to
// another path. Every other character is escaped in the address of the realm.
func validRealm(name string) bool {
	return name != "" && name != "." && name != ".." && !strings.Contains(name, "/") && len(name) <= maxRealmNameBytes
}

// realmSource returns the source of the realm, adding it and starting its
// first load when no token named that realm before. It returns
// [ErrKeyUnknown] when the ceiling of [maxLoadsPerMinute] loads refuses
// another, and when the Set already holds [Options.maxRealms] realms. A realm
// that failed to load stays for a minute, so its tokens send no request, and
// then leaves the Set at the next new realm or the next [Set.Refresh]. Names
// that exist on no Keycloak therefore cannot fill it. The ceiling comes first
// because a stream of such names can reach this code on every request.
func (s *Set) realmSource(ctx context.Context, name string) (*source, error) {
	if src, ok := s.knownRealm(name); ok {
		return src, nil
	}
	s.realmsMu.Lock()
	defer s.realmsMu.Unlock()
	if src, ok := s.realms[name]; ok {
		return src, nil
	}
	now := s.opts.now()
	if !s.loads.take(now) {
		s.warnOnce(now, "trusted providers: realm %q is not loaded, and its tokens are refused for now: the pod started %d key loads in the last minute, the most it allows", name, maxLoadsPerMinute)
		return nil, ErrKeyUnknown
	}
	s.dropFailedRealms(now)
	if len(s.realms) >= s.opts.maxRealms {
		s.warnOnce(now, "trusted providers: realm %q is not loaded, and its tokens are refused: the pod holds %d realms, the most it keeps", name, s.opts.maxRealms)
		return nil, ErrKeyUnknown
	}
	src := s.newSource(s.realmProvider(name), s.keycloakClient, false)
	s.realms[name] = src
	src.onDemand.begin(ctx, now)
	return src, nil
}

func (s *Set) knownRealm(name string) (*source, bool) {
	s.realmsMu.RLock()
	defer s.realmsMu.RUnlock()
	src, ok := s.realms[name]
	return src, ok
}

// dropFailedRealms removes the realms that are not required, never loaded a
// usable key, and started no load for a minute. The caller holds realmsMu for
// writing.
func (s *Set) dropFailedRealms(now time.Time) {
	for name, src := range s.realms {
		if !src.required && !src.loaded.Load() && src.onDemand.idle(now) {
			delete(s.realms, name)
		}
	}
}

func (s *Set) realmProvider(name string) *Provider {
	return &Provider{
		ID:     realmIDPrefix + name,
		Issuer: strings.TrimRight(s.keycloakURL, "/") + realmsPath + url.PathEscape(name),
	}
}

// realmSources returns the sources of the realms.
func (s *Set) realmSources() []*source {
	s.realmsMu.RLock()
	defer s.realmsMu.RUnlock()
	out := make([]*source, 0, len(s.realms))
	for _, src := range s.realms {
		out = append(out, src)
	}
	return out
}
