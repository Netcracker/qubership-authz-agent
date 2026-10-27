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

// Package keys holds the signing keys of the trusted issuers and finds the
// key a token asks for. An issuer is a [Provider] with a fixed iss, or a realm
// of a [Keycloak]. A realm that the configuration does not require is loaded
// when the first token names it.
//
// [ReadConfig] reads the trusted providers file, and [New] builds a [Set] from
// it. [Set.Run] loads the keys of the required sources, retrying until they
// arrive, and reloads every source on an interval, which also drops the keys an
// issuer no longer publishes. [Set.Ready] reports whether the required
// keys have arrived; keys that do not arrive stop nothing but readiness.
//
// [Set.Lookup] finds a key among the keys loaded. [Set.LookupOrReload] first
// reloads the issuer of a token whose key is not loaded, so a key that an
// issuer rotates in is found by the first token that needs it rather than at
// the next scheduled reload.
//
// A reload that fails keeps the keys already loaded for the source; a reload
// that finds no usable signing key in its JWKS removes them.
package keys

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/http"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

// Defaults of [Options].
const (
	DefaultHTTPTimeout     = 5 * time.Second
	DefaultRefreshInterval = time.Hour
	DefaultReloadWait      = 3 * time.Second
)

// The pauses between two attempts of a required source start at
// defaultFirstRetryDelay and double after every failure, up to maxRetryDelay.
const (
	defaultFirstRetryDelay = time.Second
	maxRetryDelay          = 10 * time.Second
)

const (
	// reloadInterval is the shortest time between the starts of two reloads
	// of one source that [Set.LookupOrReload] starts. It is also how long a
	// realm that failed to load is not asked for again.
	reloadInterval = time.Minute
	// maxLoadsPerMinute bounds the loads a [Set] starts for the tokens it
	// sees, over all its sources, per loadWindow. It bounds what a stream of
	// invented realms and kids costs Keycloak. A token that needs a load past
	// the bound is checked against the keys already loaded.
	maxLoadsPerMinute = 10
	// loadWindow is the time over which maxLoadsPerMinute counts loads.
	loadWindow = time.Minute
	// defaultMaxRealms bounds the realms a [Set] keeps.
	defaultMaxRealms = 1000
	// reloadConcurrency bounds the sources [Set.Refresh] fetches at a time,
	// so a reload of every realm does not send them all at once to Keycloak.
	reloadConcurrency = 8
	// jitterShare is the share of [Options.RefreshInterval], as a divisor,
	// that bounds the delay of one source in a reload of [Set.Run].
	jitterShare = 10
)

// Errors of [Set.Lookup] and [Set.LookupOrReload], matched with [errors.Is].
var (
	// ErrIssuerUnknown reports an issuer that is neither a [Provider] of the
	// configuration nor a realm of its [Keycloak].
	ErrIssuerUnknown = errors.New("issuer is not trusted")
	// ErrKeyUnknown reports that no loaded key of the issuer has the kid.
	ErrKeyUnknown = errors.New("no loaded key has the kid")
)

// Query names the key a token asks for.
type Query struct {
	// Issuer is the iss of the token. It selects the source of the key.
	Issuer string
	// KID is the kid of the token's header.
	KID string
}

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
	// RefreshInterval is how often [Set.Run] reloads the keys.
	RefreshInterval time.Duration
	// ReloadWait bounds how long [Set.LookupOrReload] waits for a reload.
	ReloadWait time.Duration
	// Log receives the diagnostics; nil discards them.
	Log Logger

	// firstRetryDelay is the pause after the first failed attempt of a
	// required source; each later pause doubles, up to maxRetryDelay.
	firstRetryDelay time.Duration
	// jitter returns the delay of one source in a reload of [Set.Run], at
	// least 0 and less than limit.
	jitter func(limit time.Duration) time.Duration
	// now is the clock that spaces the reloads LookupOrReload starts.
	now func() time.Time
	// maxRealms is the most realms a Set keeps.
	maxRealms int
}

func (o Options) withDefaults() Options {
	if o.HTTPTimeout <= 0 {
		o.HTTPTimeout = DefaultHTTPTimeout
	}
	if o.RefreshInterval <= 0 {
		o.RefreshInterval = DefaultRefreshInterval
	}
	if o.ReloadWait <= 0 {
		o.ReloadWait = DefaultReloadWait
	}
	if o.Log == nil {
		o.Log = discard{}
	}
	if o.firstRetryDelay <= 0 {
		o.firstRetryDelay = defaultFirstRetryDelay
	}
	if o.jitter == nil {
		o.jitter = rand.N[time.Duration]
	}
	if o.now == nil {
		o.now = time.Now
	}
	if o.maxRealms <= 0 {
		o.maxRealms = defaultMaxRealms
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
	// Provider is the provider whose JWKS lists the key. For a realm of a
	// [Keycloak], its ID is realm/<name>, and its Issuer is the address of the
	// realm under [Keycloak.URL], which need not equal the iss of a token.
	Provider *Provider
	// ID is the key's kid, unique within its provider.
	ID string
	// JWK is the public key.
	JWK jwk.Key

	// alg is the algorithm the JWK declares, "" when it declares none.
	alg string
}

// Allows reports whether a token whose header names alg may be verified
// with k: alg has to be one of the accepted asymmetric algorithms for the
// key type of k and, for an EC or OKP key, for its curve, and equal to the
// algorithm the JWK declares when it declares one.
func (k Key) Allows(alg string) bool {
	if k.alg != "" {
		return alg == k.alg
	}
	if algorithmKeyType[alg] != k.JWK.KeyType().String() {
		return false
	}
	curve, ok := algorithmCurve[alg]
	return !ok || curve == curveOf(k.JWK)
}

// AcceptsAlgorithm reports whether some key may verify a token whose header
// names alg: alg is one of the asymmetric algorithms [Key.Allows] can
// accept. A token signed with any other algorithm, "none" and HMAC among
// them, cannot be verified by any key of a [Set].
func AcceptsAlgorithm(alg string) bool {
	_, ok := algorithmKeyType[alg]
	return ok
}

// Set is the signing keys of the trusted issuers. It is safe for concurrent
// use, and [Set.Lookup] never waits for a reload.
type Set struct {
	opts Options
	// providers holds the sources of [Config.Providers] by issuer. It does
	// not change after New.
	providers map[string]*source
	// keycloakURL is [Keycloak.URL], "" without a Keycloak.
	keycloakURL string
	// keycloakClient is the one client of every realm, so the realms share
	// its connections.
	keycloakClient *http.Client
	// loads is the ceiling of [maxLoadsPerMinute] on the loads tokens start.
	loads *ceiling
	// warnings admits one warning a minute about a refused load, because a
	// stream of tokens can reach that refusal on every request.
	warnings *ceiling

	// realmsMu guards realms.
	realmsMu sync.RWMutex
	// realms holds the sources of the realms by realm name.
	realms map[string]*source
}

// New returns a [Set] for cfg, with no keys loaded yet. It fails when cfg
// breaks [Config.Validate] and when a caFile cannot be read. It logs a warning
// for every provider that does not set [Provider.Kubernetes] but has the id
// kubernetes or an address on an in-cluster name of the Kubernetes API server,
// since its tokens would get no namespace check.
func New(cfg Config, opts Options) (*Set, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	opts = opts.withDefaults()
	for _, p := range cfg.Providers {
		if !p.Kubernetes && p.looksLikeKubernetes() {
			opts.Log.Warnf("trusted providers: provider %q looks like a Kubernetes API server but does not set "+
				"\"kubernetes\": true, so its tokens get no namespace check; set it on this provider in the trusted "+
				"providers file if the provider is the API server", p.ID)
		}
	}
	s := &Set{
		opts:      opts,
		providers: make(map[string]*source, len(cfg.Providers)),
		loads:     newCeiling(maxLoadsPerMinute),
		warnings:  newCeiling(1),
		realms:    make(map[string]*source),
	}
	for _, p := range cfg.Providers {
		client, err := newClient(fmt.Sprintf("provider %q", p.ID), p.CAFile, opts.HTTPTimeout)
		if err != nil {
			return nil, err
		}
		s.providers[p.Issuer] = s.newSource(&p, client, true)
	}
	if cfg.Keycloak == nil {
		return s, nil
	}
	client, err := newClient("keycloak", cfg.Keycloak.CAFile, opts.HTTPTimeout)
	if err != nil {
		return nil, err
	}
	s.keycloakURL = cfg.Keycloak.URL
	s.keycloakClient = client
	for _, name := range cfg.Keycloak.RequiredRealms {
		s.realms[name] = s.newSource(s.realmProvider(name), client, true)
	}
	return s, nil
}

// newSource returns a source that reads the keys of p through client.
func (s *Set) newSource(p *Provider, client *http.Client, required bool) *source {
	src := &source{
		fetcher:  &fetcher{provider: p, client: client, log: s.opts.Log},
		log:      s.opts.Log,
		required: required,
	}
	src.onDemand = onDemand{
		reload: func(ctx context.Context) {
			if err := src.reload(ctx); err != nil {
				s.opts.Log.Warnf("trusted providers: reload for a token: %v", err)
			}
		},
		interval: reloadInterval,
		now:      s.opts.now,
		loads:    s.loads,
		refused: func(now time.Time) {
			s.warnOnce(now, "trusted providers: provider %q is not reloaded, and tokens that need a new key of it are refused for now: the pod started %d key loads in the last minute, the most it allows", src.id(), maxLoadsPerMinute)
		},
	}
	return src
}

// warnOnce logs a warning unless one went out in the last minute.
func (s *Set) warnOnce(now time.Time, format string, args ...any) {
	if s.warnings.take(now) {
		s.opts.Log.Warnf(format, args...)
	}
}

// Ready reports whether every required source has loaded a usable key: each
// [Config.Providers] entry and each of [Keycloak.RequiredRealms]. Once true,
// it stays true, also when a reload later removes those keys, so a Keycloak
// that fails does not take a running service out of rotation.
func (s *Set) Ready() bool {
	for _, src := range s.sources() {
		if src.required && !src.loaded.Load() {
			return false
		}
	}
	return true
}

// sources returns every source of the Set at the time of the call.
func (s *Set) sources() []*source {
	out := s.realmSources()
	for _, src := range s.providers {
		out = append(out, src)
	}
	return out
}

// Lookup returns the key q names from the keys loaded last, without a request.
// It returns [ErrIssuerUnknown] for an issuer that is neither a [Provider] nor
// a realm of the [Keycloak], and [ErrKeyUnknown] when no loaded key has q.KID.
func (s *Set) Lookup(q Query) (Key, error) {
	if src, ok := s.providers[q.Issuer]; ok {
		return src.find(q.KID)
	}
	name, ok := s.keycloakRealm(q.Issuer)
	if !ok {
		return Key{}, ErrIssuerUnknown
	}
	src, ok := s.knownRealm(name)
	if !ok {
		return Key{}, ErrKeyUnknown
	}
	return src.find(q.KID)
}

// LookupOrReload returns the key q names. When no loaded key of the issuer
// matches, it reloads the keys of that issuer, waits until the reload ends,
// ctx ends, or [Options.ReloadWait] passes, and looks again among the keys
// loaded by then. A realm no token named before is loaded the same way. The
// errors are those of [Set.Lookup].
//
// Callers that ask while such a reload runs wait for it rather than start
// another. One source reloads at most once a minute this way, a [Set] starts
// at most 10 such loads a minute over all its sources, and it keeps at most
// 1000 realms. When a limit refuses a load, the key is looked up among the keys
// already loaded and no request is sent. A reload that fails keeps the previous
// keys of the source and logs a warning, and a reload goes on after the wait
// ends.
func (s *Set) LookupOrReload(ctx context.Context, q Query) (Key, error) {
	src, err := s.sourceFor(ctx, q.Issuer)
	if err != nil {
		return Key{}, err
	}
	key, err := src.find(q.KID)
	if !errors.Is(err, ErrKeyUnknown) {
		return key, err
	}
	ctx, cancel := context.WithTimeout(ctx, s.opts.ReloadWait)
	defer cancel()
	src.onDemand.wait(ctx)
	return src.find(q.KID)
}

// sourceFor returns the source of issuer, adding a realm no token named
// before.
func (s *Set) sourceFor(ctx context.Context, issuer string) (*source, error) {
	if src, ok := s.providers[issuer]; ok {
		return src, nil
	}
	name, ok := s.keycloakRealm(issuer)
	if !ok {
		return nil, ErrIssuerUnknown
	}
	return s.realmSource(ctx, name)
}

// keycloakRealm returns the realm issuer names on the configured Keycloak.
func (s *Set) keycloakRealm(issuer string) (string, bool) {
	if s.keycloakURL == "" {
		return "", false
	}
	return realmOf(issuer)
}

// Refresh fetches the keys of every source once and replaces the loaded keys
// with them, as [Set.LookupOrReload] does for one source. The returned error
// joins the errors of the sources whose reload did not load a usable key.
// Eight sources fetch at a time. A realm that failed to load a minute or more
// ago is dropped rather than asked again.
func (s *Set) Refresh(ctx context.Context) error {
	return s.refresh(ctx, 0)
}

// refresh does the work of [Set.Refresh], with each source waiting a delay of
// its own, less than spread, before its fetch. A source whose delay outlasts
// ctx does not fetch and reports no error.
func (s *Set) refresh(ctx context.Context, spread time.Duration) error {
	s.realmsMu.Lock()
	s.dropFailedRealms(s.opts.now())
	s.realmsMu.Unlock()
	sources := s.sources()
	errs := make([]error, len(sources))
	slots := make(chan struct{}, reloadConcurrency)
	var wg sync.WaitGroup
	for i, src := range sources {
		wg.Go(func() {
			if spread > 0 && !pause(ctx, s.opts.jitter(spread)) {
				return
			}
			slots <- struct{}{}
			defer func() { <-slots }()
			errs[i] = src.reload(ctx)
		})
	}
	wg.Wait()
	return errors.Join(errs...)
}

// Run loads the required sources, retrying each with growing pauses until it
// has a usable key, and reloads every source every [Options.RefreshInterval].
// Each source waits a random delay of less than a tenth of the interval before
// its reload, so the pods of one rollout do not reload in step. It logs every
// failure and returns when ctx ends.
func (s *Set) Run(ctx context.Context) {
	var wg sync.WaitGroup
	defer wg.Wait()
	for _, src := range s.sources() {
		if src.required {
			wg.Go(func() { s.loadRequired(ctx, src) })
		}
	}
	ticker := time.NewTicker(s.opts.RefreshInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := s.refresh(ctx, s.opts.RefreshInterval/jitterShare); err != nil {
				s.opts.Log.Warnf("trusted providers: reload: %v", err)
			}
		}
	}
}

// loadRequired reloads src until it has a usable key or ctx ends.
func (s *Set) loadRequired(ctx context.Context, src *source) {
	delay := s.opts.firstRetryDelay
	for !src.loaded.Load() {
		err := src.reload(ctx)
		if err == nil || ctx.Err() != nil {
			return
		}
		s.opts.Log.Warnf("trusted providers: %v; retrying in %s", err, delay)
		if !pause(ctx, delay) {
			return
		}
		delay = min(delay*2, maxRetryDelay)
	}
}

// pause waits for d, and reports false when ctx ends first.
func pause(ctx context.Context, d time.Duration) bool {
	select {
	case <-ctx.Done():
		return false
	case <-time.After(d):
		return true
	}
}
