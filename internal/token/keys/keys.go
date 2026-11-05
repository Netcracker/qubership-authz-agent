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

// Package keys holds the signing keys of the trusted sources and finds the key
// a token asks for. A source is a [Provider] with a fixed iss, or a realm of a
// [Keycloak]. A realm that the configuration does not require is loaded when
// the first token names it.
//
// [ReadConfig] reads the trusted providers file, and [New] builds a [Set] from
// it. [Set.Run] loads the keys of the required sources, retrying until they
// arrive, and reloads every source on an interval, which also drops the keys a
// source no longer publishes. [Set.Ready] reports whether the required
// keys have arrived; keys that do not arrive stop nothing but readiness.
//
// [Set.Lookup] finds a key among the keys loaded. [Set.LookupOrReload] first
// starts an on-demand load of the source of a token whose key is not loaded,
// so a key that a source rotates in is found by the first token that needs it
// rather than at the next scheduled reload.
//
// A reload that fails keeps the keys already loaded for the source; a reload
// that finds no usable signing key in its JWKS removes them.
package keys

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/http"
	"slices"
	"strings"
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
	// reloadInterval is the shortest time between the starts of two
	// on-demand loads of one source. It is also how long a realm that failed
	// to load is not asked for again.
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
	// ErrKeyUnknown reports that no loaded key of the source has the kid.
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
	// InternalCAFile is a PEM bundle trusted together with the system roots
	// by a provider that sets [Provider.Kubernetes] and finds its keys through
	// discovery under an issuer outside its cluster. "" leaves the system
	// roots alone. The caller sets it to CERTIFICATE_FILE_PATH when
	// INTERNAL_TLS_ENABLED is on.
	InternalCAFile string
	// Log receives the diagnostics; nil discards them.
	Log Logger

	// firstRetryDelay is the pause after the first failed attempt of a
	// required source; each later pause doubles, up to maxRetryDelay.
	firstRetryDelay time.Duration
	// jitter returns the delay of one source in a reload of [Set.Run], at
	// least 0 and less than limit.
	jitter func(limit time.Duration) time.Duration
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

// Key is a public signing key and the source that published it.
type Key struct {
	// Source is the source whose JWKS lists the key.
	Source Source
	// ID is the key's kid, unique within its source.
	ID string
	// JWK is the public key.
	JWK jwk.Key

	// alg is the algorithm the JWK declares, "" when it declares none.
	alg string
}

// Source is a place that keys are read from: a realm of the [Keycloak] or an
// entry of [Config.Providers]. Exactly one of Realm and Provider is set.
type Source struct {
	// Realm is the name of a realm: the part of a token's iss after the last
	// slash, percent-decoded. Its keys are read under [Keycloak.URL], whatever
	// host the iss names. It is "" for a provider.
	Realm string
	// Provider is the entry of the configuration, nil for a realm.
	Provider *Provider
}

// ID names s in a result or a log line: the [Provider.ID] of a provider, or
// realm/ followed by the name of a realm. A realm name is up to 255 bytes of
// any text but a slash, taken from a token, so the ID of a realm can hold
// spaces, quotes, and control characters, and code that puts an ID into a log
// line, an event, or a metric label quotes or bounds it.
func (s Source) ID() string {
	if s.Provider != nil {
		return s.Provider.ID
	}
	return realmIDPrefix + s.Realm
}

// Kubernetes reports whether s is a provider marked [Provider.Kubernetes].
func (s Source) Kubernetes() bool { return s.Provider != nil && s.Provider.Kubernetes }

// label names s in a log line or an error of this package: realm "<name>" for
// a realm, provider "<id>" for a provider.
func (s Source) label() string {
	if s.Provider != nil {
		return fmt.Sprintf("provider %q", s.Provider.ID)
	}
	return fmt.Sprintf("realm %q", s.Realm)
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

// Set is the signing keys of the trusted sources. It is safe for concurrent
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
	// loads is the limit of [maxLoadsPerMinute] on the on-demand loads.
	loads *windowLimit
	// warnings admits one warning a minute about a refused load, because a
	// stream of tokens can reach that refusal on every request.
	warnings *windowLimit

	// realmsMu guards realms and nextDrop.
	realmsMu sync.RWMutex
	// realms holds the sources of the realms by realm name.
	realms map[string]*source
	// nextDrop is the earliest time at which [Set.dropFailedRealms] can drop a
	// realm. Each search of dropFailedRealms sets it, and [Set.realmSource]
	// lowers it to a minute after each realm it adds, when the search can
	// first drop that realm.
	nextDrop time.Time
}

// New returns a [Set] for cfg, with no keys loaded yet. It takes the issuer of
// a provider that sets [Provider.Kubernetes] from its [Provider.TokenFile]. When
// that issuer is outside the cluster and the provider has no JWKSURI, the
// provider sends no token, does not use its CAFile, and trusts the system roots
// together with [Options.InternalCAFile]. New fails when cfg breaks
// [Config.Validate], when such a file holds no token with an iss that is a URL,
// when an in-cluster issuer has neither a CAFile nor a JWKSURI, when two
// providers end up with one issuer, and when a CA file cannot be read.
func New(cfg Config, opts Options) (*Set, error) {
	opts = opts.withDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	cfg, err := cfg.withIssuers(opts.Log)
	if err != nil {
		return nil, err
	}
	s := &Set{
		opts:      opts,
		providers: make(map[string]*source, len(cfg.Providers)),
		loads:     newWindowLimit(maxLoadsPerMinute),
		warnings:  newWindowLimit(1),
		realms:    make(map[string]*source),
	}
	for _, p := range cfg.Providers {
		client, err := clientOf(p, opts)
		if err != nil {
			return nil, err
		}
		s.providers[p.Issuer] = s.newSource(Source{Provider: &p}, p.Issuer, client, true)
	}
	if cfg.Keycloak == nil {
		return s, nil
	}
	client, err := newClient("keycloak caFile", emptyCertPool, cfg.Keycloak.CAFile, opts.HTTPTimeout)
	if err != nil {
		return nil, err
	}
	s.keycloakURL = cfg.Keycloak.URL
	s.keycloakClient = client
	for _, name := range cfg.Keycloak.RequiredRealms {
		s.realms[name] = s.newSource(Source{Realm: name}, s.realmAddress(name), client, true)
	}
	return s, nil
}

// clientOf returns the client of p, whose issuer is filled in.
func clientOf(p Provider, opts Options) (*http.Client, error) {
	if p.discoversOutsideTheCluster() {
		return newClient(fmt.Sprintf("provider %q internal CA file", p.ID), x509.SystemCertPool, opts.InternalCAFile, opts.HTTPTimeout)
	}
	return newClient(fmt.Sprintf("provider %q caFile", p.ID), emptyCertPool, p.CAFile, opts.HTTPTimeout)
}

// newSource returns a source that reads the keys of from through client, with
// discovery under address unless a provider names its JWKSURI.
func (s *Set) newSource(from Source, address string, client *http.Client, required bool) *source {
	src := &source{
		fetcher:  &fetcher{source: from, address: address, client: client, log: s.opts.Log},
		required: required,
	}
	src.onDemand = onDemand{
		load: func(ctx context.Context) {
			if err := src.reload(ctx); err != nil {
				s.opts.Log.Warnf("trusted providers: on-demand load: %v", err)
			}
		},
		interval: reloadInterval,
		loads:    s.loads,
		refused: func(now time.Time) {
			s.warnOnce(now, "trusted providers: %s is not reloaded, and tokens that need a new key of it are refused for now: the agent started %d on-demand loads in the last minute, the most it allows", src.label(), maxLoadsPerMinute)
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
	src, realm, err := s.resolve(q.Issuer)
	if err != nil {
		return Key{}, err
	}
	if src == nil {
		var ok bool
		if src, ok = s.knownRealm(realm); !ok {
			return Key{}, ErrKeyUnknown
		}
	}
	return src.find(q.KID)
}

// LookupOrReload returns the key q names. When no loaded key of the source of
// q.Issuer matches, it starts an on-demand load of that source, waits until the
// load ends, ctx ends, or [Options.ReloadWait] passes, and looks again among
// the keys loaded by then. A realm no token named before is loaded the same
// way. The errors are those of [Set.Lookup].
//
// Callers that ask while such a load runs wait for it rather than start
// another. One source loads at most once a minute this way, a [Set] starts at
// most 10 such loads a minute over all its sources, and it keeps at most 1000
// realms. When a limit refuses a load, the key is looked up among the keys
// already loaded and no request is sent. A load that fails logs a warning and
// keeps the previous keys of the source, unless it got a JWKS without a usable
// key, which removes them. A load goes on after the wait ends.
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
	src, realm, err := s.resolve(issuer)
	if err != nil || src != nil {
		return src, err
	}
	return s.realmSource(ctx, realm)
}

// resolve returns the source of the provider whose issuer is issuer, or else,
// with a nil source, the name of the realm issuer names on the configured
// Keycloak. It returns [ErrIssuerUnknown] when issuer names neither.
func (s *Set) resolve(issuer string) (*source, string, error) {
	if src, ok := s.providers[issuer]; ok {
		return src, "", nil
	}
	name, ok := s.keycloakRealm(issuer)
	if !ok {
		return nil, "", ErrIssuerUnknown
	}
	return nil, name, nil
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
// has a line for each provider and each required realm whose reload did not
// load a usable key, in the order of their [Source.ID]. When a realm that
// tokens named fails, the error ends with one line for all such realms, because
// all realms share one Keycloak and any sender can name a realm. That line
// counts the failed realms and those of them without keys, and quotes the
// error of the failed realm whose name sorts first. Eight sources fetch at a
// time. The Set drops a realm that is not required and
// never loaded a usable key a minute after its last load started, rather than
// asking for it again; a realm that loaded keys keeps them when a later load
// fails.
func (s *Set) Refresh(ctx context.Context) error {
	return s.refresh(ctx, 0)
}

// refresh does the work of [Set.Refresh], with each source waiting a delay of
// its own, less than spread, before its fetch. A source whose delay outlasts
// ctx does not fetch and reports no error.
func (s *Set) refresh(ctx context.Context, spread time.Duration) error {
	s.realmsMu.Lock()
	s.dropFailedRealms(time.Now())
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
	return joinReloadErrors(sources, errs)
}

// joinReloadErrors joins errs, the errors of the reloads of sources by index,
// into the lines [Set.Refresh] describes.
func joinReloadErrors(sources []*source, errs []error) error {
	type failure struct {
		id  string
		err error
	}
	var own []failure
	var named, failed, keyless int
	var firstName string
	var firstErr error
	for i, src := range sources {
		from := src.fetcher.source
		if from.Provider != nil || src.required {
			if errs[i] != nil {
				own = append(own, failure{from.ID(), errs[i]})
			}
			continue
		}
		named++
		if errs[i] == nil {
			continue
		}
		failed++
		if src.current.Load() == nil {
			keyless++
		}
		if firstErr == nil || from.Realm < firstName {
			firstName, firstErr = from.Realm, errs[i]
		}
	}
	slices.SortFunc(own, func(a, b failure) int { return strings.Compare(a.id, b.id) })
	out := make([]error, 0, len(own)+1)
	for _, f := range own {
		out = append(out, f.err)
	}
	if failed > 0 {
		out = append(out, fmt.Errorf("%d of %d realms that tokens named did not reload, %d of them without keys; the first by name: %w", failed, named, keyless, firstErr))
	}
	return errors.Join(out...)
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
