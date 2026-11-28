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
// a token asks for. A source is a single [Provider], or a realm of a realms
// provider, which the iss of a token names. A realm outside
// [Provider.ReadinessRealms] is loaded when the first token names it.
//
// [ReadDir] reads the provider files, and [New] builds a [Set] from them.
// [Set.Run] loads the keys of the required sources, retrying until they
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
	// sees, over all the sources of one provider, per loadWindow. It bounds
	// what a stream of invented realms and kids costs the server of the
	// provider. A token that needs a load past the bound is checked against
	// the keys already loaded.
	maxLoadsPerMinute = 10
	// loadWindow is the time over which maxLoadsPerMinute counts loads.
	loadWindow = time.Minute
	// defaultMaxRealms bounds the realms a [Set] keeps.
	defaultMaxRealms = 1000
	// reloadConcurrency bounds the sources [Set.Refresh] fetches at a time,
	// so a reload of every realm does not send them all at once to one
	// server.
	reloadConcurrency = 8
	// jitterShare is the share of [Options.RefreshInterval], as a divisor,
	// that bounds the delay of one source in a reload of [Set.Run].
	jitterShare = 10
)

// Errors of [Set.Lookup] and [Set.LookupOrReload], matched with [errors.Is].
var (
	// ErrIssuerUnknown reports an issuer that matches no [Provider].
	ErrIssuerUnknown = errors.New("issuer is not trusted")
	// ErrKeyUnknown reports that no loaded key of the source has the kid. From
	// [Set.LookupOrReload] it also means that the result the lookup counts is
	// an answer or a 404: a load got a JWKS or HTTP 404 from the source.
	ErrKeyUnknown = errors.New("no loaded key has the kid")
	// ErrKeysUnavailable reports that no loaded key of the source has the kid,
	// and that the result the lookup counts is a failed load, or that it counts
	// no result. [Set.LookupOrReload] says which result a lookup counts, and
	// returns this error as an [*UnavailableError] whose Reason says why.
	ErrKeysUnavailable = errors.New("the keys of the source are not available")
)

// UnavailableError is the [ErrKeysUnavailable] of one lookup.
type UnavailableError struct {
	// Reason says why the lookup counts no answer. It names no source and no
	// provider, because the signature of the token is not checked yet, and
	// the token only claims to come from that source.
	Reason string
}

// Error returns the text of [ErrKeysUnavailable] and the reason.
func (e *UnavailableError) Error() string { return ErrKeysUnavailable.Error() + ": " + e.Reason }

// Is reports whether target is [ErrKeysUnavailable].
func (e *UnavailableError) Is(target error) bool { return target == ErrKeysUnavailable }

// The reasons of an [UnavailableError] that need no value of a [Set].
var (
	// reasonFailedLoad is the reason when the result a lookup counts is a
	// failed load.
	reasonFailedLoad = "the last load of the source failed"
	// reasonLoadLimit is the reason when the limit of [maxLoadsPerMinute]
	// on-demand loads refused the load of the lookup.
	reasonLoadLimit = fmt.Sprintf("the agent started %d on-demand loads of the provider in the last minute, the most it allows for one provider", maxLoadsPerMinute)
	// reasonCallerStopped is the reason when the context of the caller ended
	// before a load stored a result the lookup counts.
	reasonCallerStopped = "the caller stopped waiting before the load ended"
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
	// HTTPTimeout bounds one JWKS request.
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
	// ID is the key's kid. A source may list several keys under one kid.
	ID string
	// JWK is the public key.
	JWK jwk.Key

	// alg is the algorithm the JWK declares, "" when it declares none.
	alg string
}

// Source is a place that keys are read from: a single provider, or a realm of
// a realms provider.
type Source struct {
	// Provider is the provider of the source. A [Key] that a [Set] returns
	// always has one.
	Provider *Provider
	// Realm is the name of a realm, the part of a token's iss in place of
	// {realm}, percent-decoded. It is "" for a single provider.
	Realm string
}

// ID names s in a log line, and [Set.Refresh] orders the lines of its error by
// it: the [Provider.ID] of a single provider, or realm/ followed by the name of
// a realm. A realm name is up to 255 bytes taken from a token, so the ID of a
// realm can hold spaces and quotes, and code that puts an ID into a log line,
// an event, or a metric label quotes or bounds it.
func (s Source) ID() string {
	if s.Realm != "" {
		return realmIDPrefix + s.Realm
	}
	return s.Provider.ID
}

// Kubernetes reports whether s belongs to the provider [KubernetesID]. The name
// of a provider is its key in the providers object of a provider file, and
// that name alone decides whether a token that a signing key of s verifies is
// a Kubernetes token.
func (s Source) Kubernetes() bool { return s.Provider.ID == KubernetesID }

// label names s in a log line or an error of this package: realm "<name>" of
// provider "<id>" for a realm, provider "<id>" for a single provider.
func (s Source) label() string {
	if s.Realm != "" {
		return fmt.Sprintf("realm %q of provider %q", s.Realm, s.Provider.ID)
	}
	return fmt.Sprintf("provider %q", s.Provider.ID)
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
	// single holds the sources of the single providers by issuer. It does not
	// change after New.
	single map[string]*source
	// templates holds the realms providers. It does not change after
	// New.
	templates []*trusted
	// warnings admits one warning a minute about a refused load, because a
	// stream of tokens can reach that refusal on every request.
	warnings *windowLimit

	// realmsMu guards realms and nextDrop.
	realmsMu sync.RWMutex
	// realms holds the sources of the realms.
	realms map[realmKey]*source
	// nextDrop is the time before which [Set.dropFailedRealms] does not search
	// the realms. Each search of dropFailedRealms sets it, and
	// [Set.realmSource] lowers it to a minute after each realm it adds, when
	// the search can first drop that realm.
	nextDrop time.Time
}

// trusted is what the sources of one provider share.
type trusted struct {
	provider *Provider
	// client is the one client of the provider, so its sources share its
	// connections.
	client *http.Client
	// loads is the limit of [maxLoadsPerMinute] on the on-demand loads of the
	// sources of this provider.
	loads *windowLimit
	// issuer and jwks split the issuerTemplate and the jwksUri of a realms
	// provider at {realm}. They are zero in a single provider.
	issuer, jwks template
}

// loadLimitReason says that the limit of on-demand loads of t refused a load.
func (t *trusted) loadLimitReason() string {
	return fmt.Sprintf("the agent started %d on-demand loads of provider %q in the last minute, the most it allows for one provider", maxLoadsPerMinute, t.provider.ID)
}

// New returns a [Set] for cfg, with no keys loaded yet. It fails when cfg
// breaks [Config.Validate], and when the file that the
// [Provider.JWKSBearerTokenFile] of a provider names cannot be read or holds
// only white space.
func New(cfg Config, opts Options) (*Set, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	for _, p := range cfg.Providers {
		if p.JWKSBearerTokenFile == "" {
			continue
		}
		if _, err := readToken(p.JWKSBearerTokenFile); err != nil {
			return nil, fmt.Errorf("%s: jwksBearerTokenFile: %w; mount the token for the API server at that path, or remove jwksBearerTokenFile where the API server serves its keys without a token", p.name(), err)
		}
	}
	opts = opts.withDefaults()
	s := &Set{
		opts:     opts,
		single:   make(map[string]*source, len(cfg.Providers)),
		warnings: newWindowLimit(1),
		realms:   make(map[realmKey]*source),
	}
	for _, p := range cfg.Providers {
		t := &trusted{provider: &p, client: newClient(opts.HTTPTimeout), loads: newWindowLimit(maxLoadsPerMinute)}
		if p.Type == Single {
			s.single[p.Issuer] = s.newSource(t, Source{Provider: t.provider}, p.JWKSURI, true)
			continue
		}
		t.issuer, t.jwks = splitTemplate(p.IssuerTemplate), splitTemplate(p.JWKSURI)
		s.templates = append(s.templates, t)
		for _, name := range p.ReadinessRealms {
			s.realms[realmKey{t, name}] = s.newSource(t, Source{Provider: t.provider, Realm: name}, t.jwks.with(name), true)
		}
	}
	return s, nil
}

// newSource returns a source of the provider t that reads the keys of from at
// the JWKS address.
func (s *Set) newSource(t *trusted, from Source, address string, required bool) *source {
	src := &source{
		fetcher:  &fetcher{source: from, address: address, client: t.client, log: s.opts.Log},
		required: required,
	}
	src.current.Store(&loadResult{result: noResult})
	src.onDemand = onDemand{
		current: &src.current,
		load: func(ctx context.Context) {
			if err := src.reload(ctx); err != nil {
				s.opts.Log.Warnf("trusted providers: on-demand load: %v", err)
			}
		},
		interval: reloadInterval,
		loads:    t.loads,
		refused: func(now time.Time) {
			s.warnOnce(now, "trusted providers: %s is not reloaded, and tokens that need a new key of it are refused for now: %s", src.label(), t.loadLimitReason())
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
// single provider, and each realm of [Provider.ReadinessRealms]. Once true, it
// stays true, also when a reload later removes those keys, so a server that
// fails does not take a running service out of rotation.
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
	for _, src := range s.single {
		out = append(out, src)
	}
	return out
}

// Lookup returns the keys q names from the keys loaded last, without a
// request: every usable signing key that the source of q.Issuer lists under
// q.KID, in the order of its JWKS. It returns [ErrIssuerUnknown] for an issuer that matches
// no provider, and [ErrKeyUnknown] when no loaded key has q.KID, whatever the
// last load ended with. The slice it returns without an error is not empty,
// and the caller does not modify it.
func (s *Set) Lookup(q Query) ([]Key, error) {
	src, t, realm, err := s.resolve(q.Issuer)
	if err != nil {
		return nil, err
	}
	if src == nil {
		var ok bool
		if src, ok = s.knownRealm(realmKey{t, realm}); !ok {
			return nil, ErrKeyUnknown
		}
	}
	return src.lookup(q.KID)
}

// LookupOrReload returns the keys q names, as [Set.Lookup] does. When no
// loaded key of the source of q.Issuer matches, it starts an on-demand load of
// that source, waits until the load ends, ctx ends, or [Options.ReloadWait]
// passes, and looks again among the keys loaded by then. A realm no token named
// before is loaded the same way. It returns [ErrIssuerUnknown] for an issuer
// that matches no provider, as [Set.Lookup] does.
//
// Callers that ask while such a load runs wait for it rather than start
// another. One source loads at most once a minute this way, a [Set] starts at
// most 10 such loads a minute over the sources of one provider, and it keeps
// at most 1000 realms. When a limit refuses a load, the key is looked up among
// the keys already loaded and no request is sent. A load that loads no usable
// key logs a warning. A 404 or a failed load keeps the previous keys of the
// source, and an answer without a usable key removes them. A load goes on
// after the wait ends.
//
// A lookup that finds no key returns the error of the result it counts: an
// answer or a 404 gives [ErrKeyUnknown], and a failed load
// [ErrKeysUnavailable]. A load ends with an answer when it gets a JWKS: a
// document of at most 1 MiB (1048576 bytes) whose member named exactly keys
// holds an array. The array need not hold the kid or any usable key. A load
// ends with a 404 when it gets HTTP 404, and as a failed load in every other
// case. The lookup counts the last result of the source, a scheduled
// [Set.Refresh] included, with two exceptions. A lookup that started or joined
// an on-demand load counts only a result stored after that load started, and a
// lookup whose load the limit of loads refused counts only a result stored
// after the refusal. When no such result is stored by the time the wait ends,
// the lookup counts no result and returns [ErrKeysUnavailable]. A realm that
// the limit of loads or of realms refuses has no result either. [Set.Lookup]
// reports none of these cases with ErrKeysUnavailable.
func (s *Set) LookupOrReload(ctx context.Context, q Query) ([]Key, error) {
	src, err := s.sourceFor(ctx, q.Issuer)
	if err != nil {
		return nil, err
	}
	if keys, ok := src.find(q.KID); ok {
		return keys, nil
	}
	waitCtx, cancel := context.WithTimeout(ctx, s.opts.ReloadWait)
	defer cancel()
	from, waitErr := src.onDemand.wait(waitCtx)
	// last is read once, so the keys and the result come from the same load.
	last := src.current.Load()
	if keys, ok := last.find(q.KID); ok {
		return keys, nil
	}
	if waitErr != nil && last == from {
		return nil, &UnavailableError{Reason: s.waitReason(ctx, waitErr)}
	}
	return nil, last.lookupErr()
}

// waitReason returns the reason of a wait for an on-demand load that ended
// with err before a result was stored. It names one of three causes: the limit
// of loads refused the load, the context ctx of the caller ended, or
// [Options.ReloadWait] passed.
func (s *Set) waitReason(ctx context.Context, err error) string {
	switch {
	case errors.Is(err, errLoadRefused):
		return reasonLoadLimit
	case ctx.Err() != nil:
		return reasonCallerStopped
	}
	return fmt.Sprintf("the load did not end within %s", s.opts.ReloadWait)
}

// sourceFor returns the source of issuer, adding a realm no token named
// before.
func (s *Set) sourceFor(ctx context.Context, issuer string) (*source, error) {
	src, t, realm, err := s.resolve(issuer)
	if err != nil || src != nil {
		return src, err
	}
	return s.realmSource(ctx, t, realm)
}

// resolve returns the source of the single provider whose issuer is issuer,
// or else, with a nil source, the realms provider that issuer
// matches and the realm name it puts in place of {realm}. It returns
// [ErrIssuerUnknown] when issuer matches no provider. [Config.Validate] lets
// no issuer match two providers.
func (s *Set) resolve(issuer string) (*source, *trusted, string, error) {
	if src, ok := s.single[issuer]; ok {
		return src, nil, "", nil
	}
	for _, t := range s.templates {
		if name, ok := t.issuer.realm(issuer); ok {
			return nil, t, name, nil
		}
	}
	return nil, nil, "", ErrIssuerUnknown
}

// Refresh fetches the keys of every source once and replaces the loaded keys
// with them, as [Set.LookupOrReload] does for one source. The returned error
// has a line for each single provider and each required realm whose reload did
// not load a usable key, in the order of their [Source.ID]. A realm outside
// [Provider.ReadinessRealms] whose reload did not load a usable key gives no
// line: Refresh logs one warning for each such realm instead, in the order of
// the realm names. Each warning names the realm, what its load ended with, and
// the request. Eight sources fetch at a time. The Set drops a realm that is not
// required and never loaded a usable key a minute after its last load started,
// rather than asking for it again; a realm that loaded keys once keeps its
// place.
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
	for _, err := range otherRealmErrors(sources, errs) {
		s.opts.Log.Warnf("trusted providers: reload: %v", err)
	}
	return joinReloadErrors(sources, errs)
}

// failure is the error of the reload of one source, with the key that orders
// it among the others.
type failure struct {
	key string
	err error
}

// joinReloadErrors joins errs, the errors of the reloads of sources by index,
// into the lines of the single providers and the required realms that
// [Set.Refresh] describes.
func joinReloadErrors(sources []*source, errs []error) error {
	var own []failure
	for i, src := range sources {
		if from := src.fetcher.source; errs[i] != nil && !otherRealm(src) {
			own = append(own, failure{from.ID(), errs[i]})
		}
	}
	return errors.Join(sortedErrors(own)...)
}

// otherRealmErrors returns the non-nil errors of the reloads of the realms
// outside [Provider.ReadinessRealms], in the order of the realm names. errs
// holds the error of the reload of each of sources, by index.
func otherRealmErrors(sources []*source, errs []error) []error {
	var others []failure
	for i, src := range sources {
		if errs[i] != nil && otherRealm(src) {
			others = append(others, failure{src.fetcher.source.Realm, errs[i]})
		}
	}
	return sortedErrors(others)
}

// otherRealm reports whether src is a realm outside [Provider.ReadinessRealms],
// the one kind of source that is not required.
func otherRealm(src *source) bool { return !src.required }

// sortedErrors returns the errors of failures in the order of their keys.
func sortedErrors(failures []failure) []error {
	slices.SortFunc(failures, func(a, b failure) int { return strings.Compare(a.key, b.key) })
	out := make([]error, len(failures))
	for i, f := range failures {
		out[i] = f.err
	}
	return out
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
