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
// or a realm of a [Keycloak]. It is safe for concurrent use, and find never
// waits for a load.
type source struct {
	fetcher *fetcher
	// required marks a source [Set.Ready] waits for.
	required bool
	// onDemand runs the on-demand loads of [Set.LookupOrReload].
	onDemand onDemand

	// reloading serializes the fetches of this source.
	reloading sync.Mutex
	// current holds the keys loaded last. It is nil before the first load and
	// after a reload that finds no usable signing key.
	current atomic.Pointer[[]Key]
	// loaded is set by the first load that finds a usable key, and stays set.
	loaded atomic.Bool
	// unanswered is set while the last load got no answer about the keys of
	// the source. A JWKS without a usable key is an answer, and so is the 404
	// of a realm that holds no keys. A load writes it after the keys.
	unanswered atomic.Bool
}

// label names the source in a log line or an error: realm "<name>" for a realm
// of a Keycloak, provider "<id>" for an entry of [Config.Providers].
func (src *source) label() string { return src.fetcher.source.label() }

// find returns the key with the given kid among the keys loaded last, and
// [ErrKeyUnknown] when there is none. [fetcher.parseJWKS] keeps one key per
// kid.
func (src *source) find(kid string) (Key, error) {
	var loaded []Key
	if p := src.current.Load(); p != nil {
		loaded = *p
	}
	i := slices.IndexFunc(loaded, func(k Key) bool { return k.ID == kid })
	if i < 0 {
		return Key{}, ErrKeyUnknown
	}
	return loaded[i], nil
}

// reload fetches the keys once and replaces the loaded ones. A fetch that
// fails keeps them, and a JWKS without a usable signing key removes them, so
// the tokens they signed are refused. Both return an error that names the
// source and what happened to its keys.
func (src *source) reload(ctx context.Context) error {
	src.reloading.Lock()
	defer src.reloading.Unlock()

	fetched, err := src.fetcher.fetch(ctx)
	var previous []Key
	if p := src.current.Load(); p != nil {
		previous = *p
	}
	defer func() { src.unanswered.Store(src.gotNoAnswer(err, len(previous) > 0)) }()
	switch {
	case errors.Is(err, errNoUsableKey):
		src.current.Store(nil)
		return fmt.Errorf("%s has no keys, and its tokens are refused until a reload finds a usable key: %w", src.label(), err)
	case err != nil && len(previous) == 0:
		return fmt.Errorf("%s has no keys: %w", src.label(), err)
	case err != nil:
		return fmt.Errorf("%s keeps its previous keys: %w", src.label(), err)
	}
	src.current.Store(&fetched)
	src.loaded.Store(true)
	if !sameKIDs(previous, fetched) {
		src.fetcher.log.Infof("trusted providers: %s now publishes %d signing keys", src.label(), len(fetched))
	}
	return nil
}

// gotNoAnswer reports whether err, the result of a fetch, says nothing about
// the keys of the source, which held keys before the fetch when holdsKeys is
// set. A 404 is an answer only for a realm with no keys, because a token that
// names a realm the Keycloak does not hold gets that 404. A realm with keys
// existed when it loaded them, and a provider is one the configuration names
// wrongly or that does not publish its keys there.
func (src *source) gotNoAnswer(err error, holdsKeys bool) bool {
	unknownRealm := errors.Is(err, errNotFound) && src.fetcher.source.Provider == nil && !holdsKeys
	return err != nil && !errors.Is(err, errNoUsableKey) && !unknownRealm
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
