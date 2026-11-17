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
	"errors"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"
)

// source is the signing keys of one source: a [Provider] of the configuration
// or a realm of a [Keycloak]. It is safe for concurrent use, and a lookup
// through current never waits for a load.
type source struct {
	fetcher *fetcher
	// required marks a source [Set.Ready] waits for.
	required bool
	// onDemand runs the on-demand loads of [Set.LookupOrReload].
	onDemand onDemand

	// reloading serializes the fetches of this source.
	reloading sync.Mutex
	// current holds what the last load left, and an empty loadResult until the
	// first load ends.
	current atomic.Pointer[loadResult]
	// loaded is set by the first load that finds a usable key, and stays set.
	loaded atomic.Bool
}

// loadResult is what a load leaves for the lookups after it: the keys, and
// whether the source answered. One value holds both, so a lookup reads them
// from the same load.
type loadResult struct {
	// keys holds the keys loaded last: those of this load, or those it kept
	// when it failed. It is nil when no load found a usable signing key, and
	// after a load that got a JWKS without one.
	keys []Key
	// answered reports whether the source answered this load, as
	// [ErrKeysUnavailable] defines it.
	answered bool
}

// find returns the key with the given kid among the keys of r, and
// [ErrKeyUnknown] when there is none. [fetcher.parseJWKS] keeps one key per
// kid.
func (r *loadResult) find(kid string) (Key, error) {
	if i := slices.IndexFunc(r.keys, func(k Key) bool { return k.ID == kid }); i >= 0 {
		return r.keys[i], nil
	}
	return Key{}, ErrKeyUnknown
}

// label names the source in a log line or an error: realm "<name>" for a realm
// of a Keycloak, provider "<id>" for an entry of [Config.Providers].
func (src *source) label() string { return src.fetcher.source.label() }

// reload fetches the keys once and replaces the loaded ones. A fetch that
// fails keeps them, and a JWKS without a usable signing key removes them, so
// the tokens they signed are refused. Both return an error that names the
// source and what happened to its keys.
func (src *source) reload(ctx context.Context) error {
	src.reloading.Lock()
	defer src.reloading.Unlock()

	fetched, err := src.fetcher.fetch(ctx)
	previous := src.current.Load().keys
	answered := src.answered(err, len(previous) > 0)
	switch {
	case errors.Is(err, errNoUsableKey):
		src.current.Store(&loadResult{answered: answered})
		return fmt.Errorf("%s has no keys, and its tokens are refused until a reload finds a usable key: %w", src.label(), err)
	case err != nil:
		src.current.Store(&loadResult{keys: previous, answered: answered})
		if len(previous) == 0 {
			return fmt.Errorf("%s has no keys: %w", src.label(), err)
		}
		return fmt.Errorf("%s keeps its previous keys: %w", src.label(), err)
	}
	src.current.Store(&loadResult{keys: fetched, answered: answered})
	src.loaded.Store(true)
	if !sameKIDs(previous, fetched) {
		src.fetcher.log.Infof("trusted providers: %s now publishes %d signing keys", src.label(), len(fetched))
	}
	return nil
}

// answered reports whether err, the result of a fetch, is an answer of the
// source. holdsKeys reports whether the source held keys before the fetch. No
// error and a JWKS without a usable signing key are answers. So is
// [errRealmMissing] for a realm that holds no keys, and every other error is
// not. A realm that holds keys existed when it loaded them, so its 404 is a
// failed reload. A provider is named by the configuration, so its 404 means
// that its address is wrong. A realm in keycloak.requiredRealms counts like any
// other realm, although the configuration names it too. Its address is built
// from keycloak.url, which every realm shares, so with a wrong keycloak.url no
// realm in keycloak.requiredRealms loads keys, and [Set.Ready] stays false
// while that list names one. Once a required realm has loaded keys, an
// [errRealmMissing] of another realm means that the Keycloak does not hold it.
func (src *source) answered(err error, holdsKeys bool) bool {
	missingRealm := errors.Is(err, errRealmMissing) && src.fetcher.source.Provider == nil && !holdsKeys
	return err == nil || errors.Is(err, errNoUsableKey) || missingRealm
}

func sameKIDs(a, b []Key) bool {
	ids := func(keys []Key) []string {
		out := make([]string, len(keys))
		for i, k := range keys {
			out[i] = k.ID
		}
		slices.Sort(out)
		return out
	}
	return slices.Equal(ids(a), ids(b))
}
