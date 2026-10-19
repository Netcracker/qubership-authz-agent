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

// Package keys holds the signing keys of the trusted identity providers and
// finds the key a token's kid names. A provider is any OIDC provider: the
// package reads its JWKS, through discovery or directly, and knows nothing
// else about it.
//
// [ReadConfig] reads the trusted providers file. [Load] fetches every
// provider's keys and fails unless all of them arrive. [Set.Lookup] and
// [Set.Resolve] find a key by kid; with [Options.ReloadOnUnknownKID] set,
// Resolve also reloads the keys when the kid is unknown. [Set.Run] reloads
// them on a fixed interval. A reload that fails for a provider keeps the
// keys already loaded for it.
package keys

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

// Defaults of [Options].
const (
	DefaultHTTPTimeout        = 5 * time.Second
	DefaultStartupTimeout     = time.Minute
	DefaultRefreshInterval    = 24 * time.Hour
	DefaultUnknownKeyInterval = 5 * time.Minute
)

// The pauses between two attempts in Load start at defaultFirstRetryDelay
// and double after every failure, up to maxRetryDelay.
const (
	defaultFirstRetryDelay = time.Second
	maxRetryDelay          = 10 * time.Second
)

// Logger receives the diagnostics.
type Logger interface {
	Infof(format string, args ...any)
	Warnf(format string, args ...any)
}

// Options tunes how a [Set] fetches and reloads keys. A zero field takes its
// default.
type Options struct {
	// HTTPTimeout bounds one discovery or JWKS request.
	HTTPTimeout time.Duration
	// StartupTimeout bounds how long [Load] retries a provider whose keys
	// could not be fetched.
	StartupTimeout time.Duration
	// RefreshInterval is how often [Set.Run] reloads the keys.
	RefreshInterval time.Duration
	// ReloadOnUnknownKID makes [Set.Resolve] reload the keys when no
	// provider published the kid it is asked for, so a key a provider
	// rotated in is found before the next reload of [Set.Run]. When it is
	// unset, Resolve sends no request for an unknown kid and finds a rotated
	// key only after the next reload or a restart.
	ReloadOnUnknownKID bool
	// UnknownKeyInterval is the shortest time between a reload and the next
	// one an unknown kid starts in [Set.Resolve] with ReloadOnUnknownKID set.
	UnknownKeyInterval time.Duration
	// Log receives the diagnostics; nil discards them.
	Log Logger

	// firstRetryDelay is the pause after the first failed attempt in Load;
	// each later pause doubles, up to maxRetryDelay.
	firstRetryDelay time.Duration
	// now is the clock UnknownKeyInterval is measured with.
	now func() time.Time
}

func (o Options) withDefaults() Options {
	if o.HTTPTimeout <= 0 {
		o.HTTPTimeout = DefaultHTTPTimeout
	}
	if o.StartupTimeout <= 0 {
		o.StartupTimeout = DefaultStartupTimeout
	}
	if o.RefreshInterval <= 0 {
		o.RefreshInterval = DefaultRefreshInterval
	}
	if o.UnknownKeyInterval <= 0 {
		o.UnknownKeyInterval = DefaultUnknownKeyInterval
	}
	if o.Log == nil {
		o.Log = discard{}
	}
	if o.firstRetryDelay <= 0 {
		o.firstRetryDelay = defaultFirstRetryDelay
	}
	if o.now == nil {
		o.now = time.Now
	}
	return o
}

type discard struct{}

func (discard) Infof(string, ...any) {
	// The message is dropped: Options.Log is nil.
}

func (discard) Warnf(string, ...any) {
	// The message is dropped: Options.Log is nil.
}

// Key is a public signing key and the provider that published it.
type Key struct {
	// Provider is the provider whose JWKS lists the key.
	Provider *Provider
	// ID is the key's kid, unique across all providers of a [Set].
	ID string
	// JWK is the public key.
	JWK jwk.Key

	// alg is the algorithm the JWK declares, "" when it declares none.
	alg string
}

// Allows reports whether a token whose header names alg may be verified
// with k: alg has to be one of the accepted asymmetric algorithms for the
// key type of k, and equal to the algorithm the JWK declares when it
// declares one.
func (k Key) Allows(alg string) bool {
	if k.alg != "" {
		return alg == k.alg
	}
	return algorithmKeyType[alg] == k.JWK.KeyType().String()
}

// AcceptsAlgorithm reports whether some key may verify a token whose header
// names alg: alg is one of the asymmetric algorithms [Key.Allows] can
// accept. A token signed with any other algorithm, "none" and HMAC among
// them, cannot be verified by any key of a [Set].
func AcceptsAlgorithm(alg string) bool {
	_, ok := algorithmKeyType[alg]
	return ok
}

// Set is the signing keys of a fixed list of providers, indexed by kid. It
// is safe for concurrent use, and [Set.Lookup] never waits for a reload.
type Set struct {
	fetchers []*fetcher
	opts     Options
	current  atomic.Pointer[snapshot]

	// reloading serializes Refresh.
	reloading sync.Mutex

	mu         sync.Mutex
	lastReload time.Time
	// inflight is closed when the reload an unknown kid started ends; nil
	// while none runs.
	inflight chan struct{}
}

// snapshot is one consistent generation of the keys; a reload replaces it
// whole.
type snapshot struct {
	byKID      map[string]Key
	byProvider map[string][]Key
}

// Load fetches the keys of every provider in cfg and returns them as a
// [Set]. A provider whose keys cannot be fetched is retried with growing
// pauses until [Options.StartupTimeout] passes or ctx ends; Load then fails
// with an error that names every such provider and the last reason. It also
// fails when cfg breaks [Config.Validate], when a caFile cannot be read, and
// when two providers publish the same kid.
func Load(ctx context.Context, cfg Config, opts Options) (*Set, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	opts = opts.withDefaults()
	s := &Set{opts: opts}
	for _, p := range cfg.Providers {
		f, err := newFetcher(&p, opts.HTTPTimeout, opts.Log)
		if err != nil {
			return nil, err
		}
		s.fetchers = append(s.fetchers, f)
	}
	loadCtx, cancel := context.WithTimeout(ctx, opts.StartupTimeout)
	defer cancel()
	results := make([][]Key, len(s.fetchers))
	errs := make([]error, len(s.fetchers))
	var wg sync.WaitGroup
	for i, f := range s.fetchers {
		wg.Go(func() { results[i], errs[i] = s.fetchWithRetry(loadCtx, f) })
	}
	wg.Wait()
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	byProvider := make(map[string][]Key, len(s.fetchers))
	for i, f := range s.fetchers {
		byProvider[f.provider.ID] = results[i]
		opts.Log.Infof("trusted providers: provider %q contributed %d signing keys", f.provider.ID, len(results[i]))
	}
	snap, err := s.newSnapshot(byProvider)
	if err != nil {
		return nil, err
	}
	s.current.Store(snap)
	s.lastReload = opts.now()
	return s, nil
}

// fetchWithRetry fetches the keys of one provider until an attempt succeeds
// or ctx ends. The error names the provider and carries the reason of the
// last attempt that ended on its own, not the cancellation that cut short
// the one after it.
func (s *Set) fetchWithRetry(ctx context.Context, f *fetcher) ([]Key, error) {
	delay := s.opts.firstRetryDelay
	var last error
	for {
		keys, err := f.fetch(ctx)
		if err == nil {
			return keys, nil
		}
		if last == nil || ctx.Err() == nil {
			last = err
		}
		if ctx.Err() != nil {
			return nil, fmt.Errorf("provider %q: %w", f.provider.ID, last)
		}
		s.opts.Log.Warnf("trusted providers: provider %q: %v; retrying in %s", f.provider.ID, err, delay)
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, fmt.Errorf("provider %q: %w", f.provider.ID, last)
		case <-timer.C:
		}
		delay = min(delay*2, maxRetryDelay)
	}
}

// newSnapshot indexes the keys of every provider by kid; a kid two
// providers publish is an error, because the kid alone could not tell which
// provider's audiences apply.
func (s *Set) newSnapshot(byProvider map[string][]Key) (*snapshot, error) {
	byKID := make(map[string]Key)
	for _, f := range s.fetchers {
		for _, k := range byProvider[f.provider.ID] {
			if earlier, taken := byKID[k.ID]; taken {
				return nil, fmt.Errorf("kid %q is published by providers %q and %q", k.ID, earlier.Provider.ID, f.provider.ID)
			}
			byKID[k.ID] = k
		}
	}
	return &snapshot{byKID: byKID, byProvider: byProvider}, nil
}

// Lookup returns the key published under kid, from the keys loaded last.
func (s *Set) Lookup(kid string) (Key, bool) {
	k, ok := s.current.Load().byKID[kid]
	return k, ok
}

// Resolve returns the key published under kid. When no provider published
// it and [Options.ReloadOnUnknownKID] is unset, Resolve reports false at
// once. With the option set, Resolve waits for a reload of every
// provider's keys and looks again: the reload another call already
// started, or one it starts when the previous reload began at least
// [Options.UnknownKeyInterval] ago; otherwise it reports false at once.
// The wait ends early when ctx ends; the reload itself carries on.
func (s *Set) Resolve(ctx context.Context, kid string) (Key, bool) {
	if k, ok := s.Lookup(kid); ok {
		return k, true
	}
	if !s.opts.ReloadOnUnknownKID {
		return Key{}, false
	}
	done := s.reloadForUnknownKID(kid)
	if done == nil {
		return Key{}, false
	}
	select {
	case <-done:
	case <-ctx.Done():
		return Key{}, false
	}
	return s.Lookup(kid)
}

// reloadForUnknownKID returns a channel closed when the reload ends: the one
// already running, or one it starts. It returns nil when the interval since
// the previous reload is too short.
func (s *Set) reloadForUnknownKID(kid string) <-chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.inflight != nil {
		return s.inflight
	}
	if s.opts.now().Sub(s.lastReload) < s.opts.UnknownKeyInterval {
		return nil
	}
	done := make(chan struct{})
	s.inflight = done
	go func() {
		defer func() {
			s.mu.Lock()
			s.inflight = nil
			s.mu.Unlock()
			close(done)
		}()
		s.opts.Log.Infof("trusted providers: kid %q is unknown; reloading the keys", kid)
		// The reload outlives the request that asked for it, so it does not
		// take the request's context; HTTPTimeout bounds each fetch.
		if err := s.Refresh(context.Background()); err != nil {
			s.opts.Log.Warnf("trusted providers: reload: %v", err)
		}
	}()
	return done
}

// Refresh fetches the keys of every provider once and replaces the loaded
// keys with them. A provider whose fetch fails keeps its previous keys, and
// its error is part of the returned one. When the new keys of two providers
// share a kid, nothing is replaced. Refresh calls run one at a time.
func (s *Set) Refresh(ctx context.Context) error {
	s.reloading.Lock()
	defer s.reloading.Unlock()
	s.mu.Lock()
	s.lastReload = s.opts.now()
	s.mu.Unlock()

	old := s.current.Load()
	results := make([][]Key, len(s.fetchers))
	errs := make([]error, len(s.fetchers))
	var wg sync.WaitGroup
	for i, f := range s.fetchers {
		wg.Go(func() { results[i], errs[i] = f.fetch(ctx) })
	}
	wg.Wait()

	byProvider := make(map[string][]Key, len(s.fetchers))
	var failures []error
	for i, f := range s.fetchers {
		id := f.provider.ID
		if errs[i] != nil {
			byProvider[id] = old.byProvider[id]
			failures = append(failures, fmt.Errorf("provider %q keeps its previous keys: %w", id, errs[i]))
			continue
		}
		byProvider[id] = results[i]
		if !sameKIDs(old.byProvider[id], results[i]) {
			s.opts.Log.Infof("trusted providers: provider %q now publishes %d signing keys", id, len(results[i]))
		}
	}
	snap, err := s.newSnapshot(byProvider)
	if err != nil {
		return errors.Join(append(failures, fmt.Errorf("every provider keeps its previous keys: %w", err))...)
	}
	s.current.Store(snap)
	return errors.Join(failures...)
}

// Run calls [Set.Refresh] every [Options.RefreshInterval] until ctx ends,
// and logs a reload that fails.
func (s *Set) Run(ctx context.Context) {
	ticker := time.NewTicker(s.opts.RefreshInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := s.Refresh(ctx); err != nil {
				s.opts.Log.Warnf("trusted providers: reload: %v", err)
			}
		}
	}
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
