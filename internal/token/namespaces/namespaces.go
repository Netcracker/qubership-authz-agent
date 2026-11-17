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

// Package namespaces decides which Kubernetes namespaces a service account
// token may come from. The allowed namespaces are the service's own
// namespace and the origin and the peer namespace of the composite baseline
// and of every satellite in the topology file. [Allowlist.Admit] applies
// them, as [verify.Options.Admit], to every Kubernetes token, and
// [Allowlist.Run] keeps them current.
package namespaces

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"authz-agent/internal/token/verify"
)

// Defaults of [Options].
const (
	DefaultTopologyFile    = "/etc/topology/data"
	DefaultRefreshInterval = 20 * time.Second
)

// Logger receives the diagnostics.
type Logger interface {
	Warnf(format string, args ...any)
}

// Options tunes an [Allowlist]. A zero field takes its default.
type Options struct {
	// TopologyFile is the JSON file that describes the composite topology.
	TopologyFile string
	// Namespace is the service's own namespace. It is always allowed, beside
	// the namespaces the topology file names; an empty Namespace adds none.
	Namespace string
	// RefreshInterval is how often [Allowlist.Run] reads the file again.
	RefreshInterval time.Duration
	// Log receives the diagnostics; nil discards them.
	Log Logger
}

// Allowlist holds the allowed namespaces. It is safe for concurrent use,
// and [Allowlist.Allows] never reads the file or waits for a read.
type Allowlist struct {
	opts    Options
	allowed atomic.Pointer[map[string]bool]

	// reading serializes reads of the topology file and guards fault.
	reading sync.Mutex
	// fault is the cause of the last warning, kept until a read finds
	// another cause or none, so that a cause is logged when it appears
	// rather than on every read.
	fault string
}

// New reads the topology file and returns an Allowlist of the namespaces it
// allows. The namespaces change only when [Allowlist.Run] reads the file
// again.
func New(opts Options) *Allowlist {
	if opts.TopologyFile == "" {
		opts.TopologyFile = DefaultTopologyFile
	}
	if opts.RefreshInterval <= 0 {
		opts.RefreshInterval = DefaultRefreshInterval
	}
	if opts.Log == nil {
		opts.Log = discard{}
	}
	a := &Allowlist{opts: opts}
	a.reload()
	return a
}

// Allows reports whether a token from namespace is allowed, by the
// namespaces the topology file allowed when it was read last.
func (a *Allowlist) Allows(namespace string) bool {
	return (*a.allowed.Load())[namespace]
}

// Run reads the topology file again every [Options.RefreshInterval] until
// ctx ends.
func (a *Allowlist) Run(ctx context.Context) {
	ticker := time.NewTicker(a.opts.RefreshInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.reload()
		}
	}
}

// reload reads the topology file and replaces the allowed namespaces with
// the ones it allows.
func (a *Allowlist) reload() {
	a.reading.Lock()
	defer a.reading.Unlock()
	allowed := a.load()
	a.allowed.Store(&allowed)
}

// Admit refuses a token for which [verify.Token.Kubernetes] reports true
// unless the namespace member of its kubernetes.io claim names an allowed
// namespace, and passes every other token. The refusal carries
// [verify.CodeNamespaceNotAllowed]. Admit is meant to be set as
// [verify.Options.Admit].
func (a *Allowlist) Admit(tok *verify.Token) *verify.Error {
	if !tok.Kubernetes() {
		return nil
	}
	namespace, ok := namespaceOf(tok)
	if !ok {
		return &verify.Error{Code: verify.CodeNamespaceNotAllowed, Detail: "token names no kubernetes.io namespace"}
	}
	if !a.Allows(namespace) {
		return &verify.Error{
			Code:   verify.CodeNamespaceNotAllowed,
			Detail: fmt.Sprintf("namespace %.64q is not an allowed namespace", namespace),
		}
	}
	return nil
}

// namespaceOf returns the namespace member of the kubernetes.io claim of
// tok, and false when the claim holds no such non-empty string. Member
// names match exactly, case included.
func namespaceOf(tok *verify.Token) (string, bool) {
	raw, _ := tok.Claim("kubernetes.io")
	var k8s map[string]json.RawMessage
	var namespace string
	if json.Unmarshal(raw, &k8s) != nil || json.Unmarshal(k8s["namespace"], &namespace) != nil {
		return "", false
	}
	return namespace, namespace != ""
}

// topology is the part of the topology file the allowlist reads.
type topology struct {
	Composite *struct {
		Baseline   *domain   `json:"baseline"`
		Satellites []*domain `json:"satellites"`
	} `json:"composite"`
}

// domain is one blue-green domain of the composite: the namespaces of its
// origin and peer.
type domain struct {
	Origin string `json:"origin"`
	Peer   string `json:"peer"`
}

// errNoNamespace is the cause logged for a composite whose domains name no
// origin or peer namespace.
var errNoNamespace = errors.New("composite names no origin or peer namespace")

// load returns Options.Namespace, unless it is empty, together with the
// namespaces the topology file names. A file that cannot be read or parsed,
// or whose composite names no origin or peer namespace, names none and is
// logged; the same cause is logged again only after a read that finds
// another cause or none. A file without a composite names none and is not
// logged: it describes an installation outside a composite.
func (a *Allowlist) load() map[string]bool {
	allowed, err := a.read()
	if a.opts.Namespace != "" {
		allowed[a.opts.Namespace] = true
	}
	var cause string
	if err != nil {
		cause = err.Error()
	}
	if cause != "" && cause != a.fault {
		if a.opts.Namespace == "" {
			a.opts.Log.Warnf("topology file %s: %v; allowing no namespace", a.opts.TopologyFile, err)
		} else {
			a.opts.Log.Warnf("topology file %s: %v; allowing namespace %q alone", a.opts.TopologyFile, err, a.opts.Namespace)
		}
	}
	a.fault = cause
	return allowed
}

// read returns the origin and the peer namespace of every domain of the
// composite in the topology file. When the file cannot be read or parsed,
// or its composite names no origin or peer namespace, it returns an empty
// map and the cause.
func (a *Allowlist) read() (map[string]bool, error) {
	raw, err := os.ReadFile(a.opts.TopologyFile)
	if err != nil {
		return map[string]bool{}, err
	}
	var t topology
	if err = json.Unmarshal(raw, &t); err != nil {
		return map[string]bool{}, err
	}
	named := t.namespaces()
	if t.Composite != nil && len(named) == 0 {
		return named, errNoNamespace
	}
	return named, nil
}

func (t topology) namespaces() map[string]bool {
	allowed := map[string]bool{}
	if t.Composite == nil {
		return allowed
	}
	for _, d := range append([]*domain{t.Composite.Baseline}, t.Composite.Satellites...) {
		if d == nil {
			continue
		}
		for _, namespace := range []string{d.Origin, d.Peer} {
			if namespace != "" {
				allowed[namespace] = true
			}
		}
	}
	return allowed
}

type discard struct{}

func (discard) Warnf(string, ...any) {
	// The message is dropped: Options.Log is nil.
}
