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
// can read. When a service answers such a request with 401, the transport
// calls [TransportOptions.Unauthorized], where [Writer.Renew] requests a new
// token unless the previous request started less than 30 seconds ago.
package outbound

import "errors"

// ErrNoToken is returned for a request that has to carry the token while
// the token function of [NewTransport] returns "".
var ErrNoToken = errors.New("outbound token is not available")

// Logger receives the diagnostics. No message carries the token.
type Logger interface {
	Infof(format string, args ...any)
	Warnf(format string, args ...any)
}

type discard struct{}

func (discard) Infof(string, ...any) {
	// The message is dropped: the caller passed no logger.
}

func (discard) Warnf(string, ...any) {
	// The message is dropped: the caller passed no logger.
}
