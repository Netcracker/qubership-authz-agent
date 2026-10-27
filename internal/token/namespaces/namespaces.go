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
// token may come from. The allowed namespaces are the origin and the peer
// namespace of the composite baseline and of every satellite in the
// topology file. [Allowlist.Admit] applies them, as [verify.Options.Admit],
// to the tokens of the providers marked
// [authz-agent/internal/token/keys.Provider.Kubernetes], and [Allowlist.Run]
// keeps them current.
package namespaces

import (
	"context"
	"encoding/json"
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
	// Namespace is the service's own namespace. It is the only namespace
	// allowed while the topology file cannot be read or parsed; once the
	// file parses, it is allowed only if the topology names it.
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

	// reading serializes reads of the topology file and guards fallback.
	reading sync.Mutex
	// fallback is whether the last read fell back to Options.Namespace; the
	// warning is logged when that starts, not on every read.
	fallback bool
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
// unless its kubernetes.io.namespace claim names an allowed namespace, and
// passes any other token. The refusal carries
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

// load reads the allowed namespaces from the topology file. A file that
// cannot be read or parsed allows the service's own namespace alone, or
// none when Options.Namespace is empty; a file without a composite allows
// none.
func (a *Allowlist) load() map[string]bool {
	raw, err := os.ReadFile(a.opts.TopologyFile)
	if err == nil {
		var t topology
		if err = json.Unmarshal(raw, &t); err == nil {
			a.fallback = false
			return t.namespaces()
		}
	}
	if !a.fallback {
		if a.opts.Namespace == "" {
			a.opts.Log.Warnf("topology file %s: %v; allowing no namespace", a.opts.TopologyFile, err)
		} else {
			a.opts.Log.Warnf("topology file %s: %v; allowing namespace %q alone", a.opts.TopologyFile, err, a.opts.Namespace)
		}
	}
	a.fallback = true
	if a.opts.Namespace == "" {
		return map[string]bool{}
	}
	return map[string]bool{a.opts.Namespace: true}
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
