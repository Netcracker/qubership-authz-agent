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

// Package outbound supplies the token the service presents on its own
// requests, such as the calls to PIPs. The token lives in a file: the
// kubelet writes a projected service account token there, or a [Writer]
// obtains one from an identity provider with client credentials and writes
// it there. A [FileSource] reads the file and follows its changes, and
// [NewTransport] adds the token, the request ID, and the tracing headers to
// the requests they are meant for at the transport, below anything a policy
// can read.
package outbound

import "errors"

// ErrNoToken is returned for a request that has to carry the token while
// the [Source] holds none.
var ErrNoToken = errors.New("outbound token is not available")

// Source supplies the current token; [*FileSource] implements it.
type Source interface {
	// Token returns the current token, or "" while there is none.
	Token() string
}

// Logger receives the diagnostics. No message carries the token.
type Logger interface {
	Infof(format string, args ...any)
	Warnf(format string, args ...any)
}

type discard struct{}

func (discard) Infof(string, ...any) {}
func (discard) Warnf(string, ...any) {}
