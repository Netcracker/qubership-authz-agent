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

// Package badrequest defines the error of a request that fails because of
// what the caller sent, so that every layer that can find such a request
// gives the same error and the public routes answer it alike.
package badrequest

// Error is a request that fails because of what the caller sent: a body
// that does not parse, a required field without a value, or a value the
// agent cannot compare within its bounds. The same request fails the same
// way again, and only a change to it helps. Find it with [errors.As]: the
// public routes answer an error that wraps one with status 400 and the
// Message of the first one in its chain, and log the whole error at debug,
// not as a failure of the agent. A layer that wraps one with context of its
// own, such as the tenant, adds it to the log and not to the response.
type Error struct {
	// Message is the whole response message, for the caller: it names the
	// part of the request that fails.
	Message string
	// Err is the error Message describes, nil where Message is the whole
	// story; [errors.Is] reaches it.
	Err error
}

func (e *Error) Error() string { return e.Message }

// Unwrap returns Err.
func (e *Error) Unwrap() error { return e.Err }
