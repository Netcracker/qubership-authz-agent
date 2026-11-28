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
	"fmt"
	"time"
)

// realmIDPrefix starts the [Source.ID] of a realm. Its slash keeps that id
// apart from the id of a provider.
const realmIDPrefix = "realm/"

// noDrop is the nextDrop that a search of [Set.dropFailedRealms] sets when the
// Set holds no realm that a later search could drop.
var noDrop = time.Date(9999, time.December, 31, 0, 0, 0, 0, time.UTC)

// realmKey identifies a realm: its realms provider and its name.
type realmKey struct {
	provider *trusted
	name     string
}

// realmSource returns the source of the realm name of the realms provider t,
// adding it and starting its first load when no token named that realm
// before. It returns an [*UnavailableError] when the limit of
// [maxLoadsPerMinute] on-demand loads of t refuses another, and when the Set
// already holds [Options.maxRealms] realms. A realm that is not required and
// never loaded a usable key stays for a minute after its last load started, so
// its tokens send no request, and the Set then drops it at the next new realm
// or the next [Set.Refresh]. Names that exist on no server therefore cannot
// fill it; a realm that loaded keys keeps its place.
//
// The iss is read before the signature verifies, so a stream of such names can
// reach this code on every request. The limit of loads comes first, and a realm
// the realm limit refuses gives its load back, because no load starts for it.
// The search for realms to drop runs only once one is due, so at the realm
// limit a token refused before then costs no search over the held realms.
func (s *Set) realmSource(ctx context.Context, t *trusted, name string) (*source, error) {
	key := realmKey{t, name}
	if src, ok := s.knownRealm(key); ok {
		return src, nil
	}
	s.realmsMu.Lock()
	defer s.realmsMu.Unlock()
	if src, ok := s.realms[key]; ok {
		return src, nil
	}
	now := time.Now()
	if !t.loads.take(now) {
		s.warnOnce(now, "trusted providers: realm %q of provider %q is not loaded, and its tokens are refused for now: %s", name, t.provider.ID, t.loadLimitReason())
		return nil, &UnavailableError{Reason: reasonLoadLimit}
	}
	s.dropFailedRealms(now)
	if len(s.realms) >= s.opts.maxRealms {
		t.loads.refund(now)
		s.warnOnce(now, "trusted providers: realm %q of provider %q is not loaded, and its tokens are refused: the agent holds %d realms, the most it keeps", name, t.provider.ID, s.opts.maxRealms)
		return nil, &UnavailableError{Reason: fmt.Sprintf("the agent holds %d realms, the most it keeps", s.opts.maxRealms)}
	}
	src := s.newSource(t, Source{Provider: t.provider, Realm: name}, t.jwks.with(name), false)
	s.realms[key] = src
	src.onDemand.begin(ctx, now)
	if due := now.Add(reloadInterval); due.Before(s.nextDrop) {
		s.nextDrop = due
	}
	return src, nil
}

func (s *Set) knownRealm(key realmKey) (*source, bool) {
	s.realmsMu.RLock()
	defer s.realmsMu.RUnlock()
	src, ok := s.realms[key]
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
	for key, src := range s.realms {
		if src.required || src.loaded.Load() {
			continue
		}
		idle, due := src.onDemand.idle(now)
		if idle {
			delete(s.realms, key)
			continue
		}
		if due.Before(next) {
			next = due
		}
	}
	s.nextDrop = next
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
