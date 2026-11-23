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

// source is the signing keys of one source: an exact provider or a realm of a
// realm-template provider. It is safe for concurrent use, and a lookup never
// waits for a load.
type source struct {
	fetcher *fetcher
	// required marks a source [Set.Ready] waits for.
	required bool
	// onDemand runs the on-demand loads of [Set.LookupOrReload].
	onDemand onDemand

	// reloading serializes the fetches of this source.
	reloading sync.Mutex
	// current holds what the last load left, and nil before the first load
	// ends.
	current atomic.Pointer[loadResult]
	// loaded is set by the first load that finds a usable key, and stays set.
	loaded atomic.Bool
}

// loadResult is what a load leaves for the lookups after it.
type loadResult struct {
	// keys holds the keys loaded last: those of this load, or those it kept
	// when it failed. It is nil when no load found a usable signing key, and
	// after a load that got a JWKS without one.
	keys []Key
}

// last returns what the last load left, and an empty loadResult before the
// first load ends.
func (src *source) last() loadResult {
	if p := src.current.Load(); p != nil {
		return *p
	}
	return loadResult{}
}

// label names the source in a log line or an error: realm "<name>" of
// provider "<id>" for a realm, provider "<id>" for an exact provider.
func (src *source) label() string { return src.fetcher.source.label() }

// find returns the key of r with the given kid, and false when there is none.
// [fetcher.parseJWKS] keeps one key per kid.
func (r loadResult) find(kid string) (Key, bool) {
	if i := slices.IndexFunc(r.keys, func(k Key) bool { return k.ID == kid }); i >= 0 {
		return r.keys[i], true
	}
	return Key{}, false
}

// find returns the key with the given kid among the keys loaded last, and
// false when there is none.
func (src *source) find(kid string) (Key, bool) { return src.last().find(kid) }

// lookup returns the key with the given kid among the keys loaded last, and
// [ErrKeyUnknown] when there is none.
func (src *source) lookup(kid string) (Key, error) {
	if key, ok := src.find(kid); ok {
		return key, nil
	}
	return Key{}, ErrKeyUnknown
}

// reload fetches the keys once and replaces the loaded ones. A fetch that
// fails keeps them, and a JWKS without a usable signing key removes them, so
// the tokens they signed are refused. Each failure returns an error that names
// the source and what happened to its keys.
func (src *source) reload(ctx context.Context) error {
	src.reloading.Lock()
	defer src.reloading.Unlock()

	fetched, err := src.fetcher.fetch(ctx)
	previous := src.last().keys
	switch {
	case errors.Is(err, errNoUsableKey):
		src.current.Store(&loadResult{})
		return fmt.Errorf("%s has no keys, and its tokens are refused until a reload finds a usable key: %w", src.label(), err)
	case err != nil:
		src.current.Store(&loadResult{keys: previous})
		if len(previous) == 0 {
			return fmt.Errorf("%s has no keys: %w", src.label(), err)
		}
		return fmt.Errorf("%s keeps its previous keys: %w", src.label(), err)
	}
	src.current.Store(&loadResult{keys: fetched})
	src.loaded.Store(true)
	if !sameKIDs(previous, fetched) {
		src.fetcher.log.Infof("trusted providers: %s now publishes %s", src.label(), countOf(len(fetched), "signing key"))
	}
	return nil
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
