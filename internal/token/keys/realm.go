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
	// realmsPath marks the iss of a realm token and is the path of a realm
	// under [Keycloak.URL].
	realmsPath = "/auth/realms/"
	// realmIDPrefix starts the [Source.ID] of a realm. Its slash keeps that
	// id apart from any id a configuration can hold.
	realmIDPrefix = "realm/"
	// maxRealmNameBytes bounds a realm name, in bytes.
	maxRealmNameBytes = 255
)

// noDrop is the nextDrop that a search of [Set.dropFailedRealms] sets when the
// Set holds no realm that a later search could drop.
var noDrop = time.Date(9999, time.December, 31, 0, 0, 0, 0, time.UTC)

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
// [ErrKeysUnavailable] when the limit of [maxLoadsPerMinute] on-demand loads
// refuses another, and when the Set already holds [Options.maxRealms] realms. A
// realm that is not required and never loaded a usable key stays for a minute
// after its last load started, so its tokens send no request, and the Set then
// drops it at the next new realm or the next [Set.Refresh]. Names that exist on
// no Keycloak therefore cannot fill it; a realm that loaded keys keeps its
// place.
//
// The iss is read before the signature verifies, so a stream of such names can
// reach this code on every request. The limit of loads comes first, and a realm
// the realm limit refuses gives its load back, because no load starts for it.
// The search for realms to drop runs only once one is due, so at the realm
// limit a token refused before then costs no search over the held realms.
func (s *Set) realmSource(ctx context.Context, name string) (*source, error) {
	if src, ok := s.knownRealm(name); ok {
		return src, nil
	}
	s.realmsMu.Lock()
	defer s.realmsMu.Unlock()
	if src, ok := s.realms[name]; ok {
		return src, nil
	}
	now := time.Now()
	if !s.loads.take(now) {
		s.warnOnce(now, "trusted providers: realm %q is not loaded, and its tokens are refused for now: the agent started %d on-demand loads in the last minute, the most it allows", name, maxLoadsPerMinute)
		return nil, ErrKeysUnavailable
	}
	s.dropFailedRealms(now)
	if len(s.realms) >= s.opts.maxRealms {
		s.loads.refund(now)
		s.warnOnce(now, "trusted providers: realm %q is not loaded, and its tokens are refused: the agent holds %d realms, the most it keeps", name, s.opts.maxRealms)
		return nil, ErrKeysUnavailable
	}
	src := s.newSource(Source{Realm: name}, s.realmAddress(name), s.keycloakClient, false)
	s.realms[name] = src
	src.onDemand.begin(ctx, now)
	if due := now.Add(reloadInterval); due.Before(s.nextDrop) {
		s.nextDrop = due
	}
	return src, nil
}

func (s *Set) knownRealm(name string) (*source, bool) {
	s.realmsMu.RLock()
	defer s.realmsMu.RUnlock()
	src, ok := s.realms[name]
	return src, ok
}

// dropFailedRealms searches the realms and drops those that are not required,
// never loaded a usable key, run no load, and started none in the last minute.
// It sets nextDrop to the earliest time at which one of the remaining such
// realms becomes due, or to noDrop when none remains. Before nextDrop it
// returns at once, without a search. The caller holds realmsMu for writing.
func (s *Set) dropFailedRealms(now time.Time) {
	if now.Before(s.nextDrop) {
		return
	}
	next := noDrop
	for name, src := range s.realms {
		if src.required || src.loaded.Load() {
			continue
		}
		idle, due := src.onDemand.idle(now)
		if idle {
			delete(s.realms, name)
			continue
		}
		if due.Before(next) {
			next = due
		}
	}
	s.nextDrop = next
}

// realmAddress returns the address of the realm under [Keycloak.URL], which
// discovery runs under.
func (s *Set) realmAddress(name string) string {
	return strings.TrimRight(s.keycloakURL, "/") + realmsPath + url.PathEscape(name)
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
