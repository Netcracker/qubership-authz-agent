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
	"maps"
	"sync"
	"sync/atomic"
)

// source is the signing keys of one source: a single provider or a realm of a
// realms provider. It is safe for concurrent use, and a lookup never
// waits for a load.
type source struct {
	fetcher *fetcher
	// required marks a source [Set.Ready] waits for.
	required bool
	// onDemand runs the on-demand loads of [Set.LookupOrReload].
	onDemand onDemand

	// reloading serializes the fetches of this source.
	reloading sync.Mutex
	// current holds what the last load that ended left, and an empty
	// loadResult before the first load ends. Each load stores a new value and
	// changes no stored one, so two values read at different times are the
	// same pointer only when no load stored a result in between.
	current atomic.Pointer[loadResult]
	// loaded is set by the first load that finds a usable key, and stays set.
	loaded atomic.Bool
}

// result is what a load that ended decides about its source.
type result int

// The values of result.
const (
	// noResult is the result of a source whose first load has not ended.
	noResult result = iota
	// answer is the result of a load that got a JWKS, as
	// [Set.LookupOrReload] defines it.
	answer
	// notFound is the result of a load that got HTTP 404.
	notFound
	// failedLoad is the result of any other load.
	failedLoad
)

// loadResult is what a load leaves for the lookups after it. One value holds
// the keys and the result, so a lookup reads both from the same load.
type loadResult struct {
	// keys holds the keys loaded last by kid, each list in the order of the
	// JWKS. After an answer they are the keys of that answer; after a 404 or a
	// failed load, the keys the source held before that load. It is nil when
	// no load found a usable signing key, and after an answer without one.
	keys   map[string][]Key
	result result
}

// last returns what the last load that ended left.
func (src *source) last() loadResult { return *src.current.Load() }

// label names the source in a log line or an error: realm "<name>" of
// provider "<id>" for a realm, provider "<id>" for a single provider.
func (src *source) label() string { return src.fetcher.source.label() }

// find returns the keys of r with the given kid in the order of the JWKS, and
// false when there is none.
func (r loadResult) find(kid string) ([]Key, bool) {
	keys, ok := r.keys[kid]
	return keys, ok
}

// find returns the keys with the given kid among the keys loaded last, and
// false when there is none.
func (src *source) find(kid string) ([]Key, bool) { return src.last().find(kid) }

// lookup returns the keys with the given kid among the keys loaded last, and
// [ErrKeyUnknown] when there is none.
func (src *source) lookup(kid string) ([]Key, error) {
	if keys, ok := src.find(kid); ok {
		return keys, nil
	}
	return nil, ErrKeyUnknown
}

// lookupErr returns the error of a lookup that counts r and finds no key in
// it, as [Set.LookupOrReload] describes. A lookup that waited for a load
// counts r only when a load stored it, so r is never noResult here; for that
// case it returns what it returns for failedLoad.
func (r *loadResult) lookupErr() error {
	if r.result == answer || r.result == notFound {
		return ErrKeyUnknown
	}
	return &UnavailableError{Reason: reasonFailedLoad}
}

// reload fetches the keys once, stores the result, and replaces the loaded
// keys. An answer with usable signing keys replaces them, and an answer
// without one removes them, so the tokens they signed are refused. A load that
// gets HTTP 404, and every other load that does not get a JWKS, keeps the
// keys. Each load that does not end with usable keys returns an error that
// names the source, what its load ended with, and what happened to its keys.
func (src *source) reload(ctx context.Context) error {
	src.reloading.Lock()
	defer src.reloading.Unlock()

	fetched, err := src.fetcher.fetch(ctx)
	previous := src.last().keys
	switch {
	case errors.Is(err, errNoUsableKey):
		src.current.Store(&loadResult{result: answer})
		return fmt.Errorf("%s has no keys, and its tokens are refused until a reload finds a usable key: %w", src.label(), err)
	case err != nil:
		result, ended := failedLoad, "a failed load"
		if isNotFound(err) {
			result, ended = notFound, "a load that got HTTP 404"
		}
		src.current.Store(&loadResult{keys: previous, result: result})
		if len(previous) == 0 {
			return fmt.Errorf("%s has no keys after %s: %w", src.label(), ended, err)
		}
		return fmt.Errorf("%s keeps its previous keys after %s: %w", src.label(), ended, err)
	}
	loaded := byKID(fetched)
	src.current.Store(&loadResult{keys: loaded, result: answer})
	src.loaded.Store(true)
	if !sameKIDs(previous, loaded) {
		src.fetcher.log.Infof("trusted providers: %s now publishes %s", src.label(), countOf(len(fetched), "signing key"))
	}
	return nil
}

// byKID groups keys by kid, each list in the order of keys.
func byKID(keys []Key) map[string][]Key {
	out := make(map[string][]Key)
	for _, k := range keys {
		out[k.ID] = append(out[k.ID], k)
	}
	return out
}

// sameKIDs reports whether a and b hold the same kids with the same number of
// keys under each.
func sameKIDs(a, b map[string][]Key) bool {
	return maps.EqualFunc(a, b, func(x, y []Key) bool { return len(x) == len(y) })
}
