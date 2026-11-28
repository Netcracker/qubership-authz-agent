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

//go:build integration

package paritysuite

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"syscall"
	"testing"
	"time"
)

// agentRestartWait bounds how long [awaitPullAfterRestart] waits for an agent
// that stopped answering to answer the pull route again. A restarted agent
// answered within about 6 s in CI, but the kubelet delays each restart of a
// container that keeps exiting twice as long as the one before, up to 300 s,
// so a run in which several cases stop the agent can wait that long before the
// agent starts at all. Tests shorten it.
var agentRestartWait = 5*time.Minute + 30*time.Second

// agentRestartPoll is how long [awaitPullAfterRestart] waits between two pulls.
const agentRestartPoll = 250 * time.Millisecond

// isAgentTransportFailure reports whether err says the agent did not answer at
// all: the connection was refused or reset, closed before the answer (EOF), or
// timed out. An HTTP answer of the agent, whatever its status, is not one.
func isAgentTransportFailure(err error) bool {
	if errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.ECONNRESET) ||
		errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

// awaitPullAfterRestart asks the agent to load the policies again and again,
// [agentRestartPoll] apart, while the pull fails with a transport failure
// (isAgentTransportFailure), for at most wait plus one pull. It returns how
// long it waited and nil once the agent loaded the policies, or the error of
// the last pull: at once for an answer of the agent other than a load, such
// as a 502, and after wait for a transport failure. The error is not an
// *[agentLoadError], so it does not repeat setupBrokenPrefix inside a report.
func awaitPullAfterRestart(ctx context.Context, wait time.Duration) (time.Duration, error) {
	start := time.Now()
	deadline := start.Add(wait)
	for {
		select {
		case <-ctx.Done():
			return time.Since(start), ctx.Err()
		case <-time.After(agentRestartPoll):
		}
		err := awaitPull(ctx)
		var notLoaded *agentLoadError
		if errors.As(err, &notLoaded) {
			err = notLoaded.err
		}
		switch {
		case err == nil:
			return time.Since(start), nil
		case !isAgentTransportFailure(err):
			return time.Since(start), fmt.Errorf("the agent answered again after it stopped answering, but did not load the policies: %w", err)
		case time.Now().After(deadline):
			return time.Since(start), fmt.Errorf("the agent did not answer the pull route within %s after it stopped answering; the last pull: %w", wait, err)
		}
	}
}

func TestIsAgentTransportFailure(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closed := "http://" + listener.Addr().String() + agentPullPath
	_ = listener.Close()
	_, refused := http.Post(closed, "", nil)
	if refused == nil {
		t.Fatalf("POST %s to a closed port succeeded", closed)
	}
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"a refused connection", fmt.Errorf("ask the agent to load the policies: %w", refused), true},
		{"a connection closed with no answer", &url.Error{Op: "Post", URL: closed, Err: io.EOF}, true},
		{"a connection closed inside the answer", &url.Error{Op: "Post", URL: closed, Err: io.ErrUnexpectedEOF}, true},
		{"a reset connection", &url.Error{Op: "Post", URL: closed, Err: syscall.ECONNRESET}, true},
		{"a timeout", &url.Error{Op: "Post", URL: closed, Err: context.DeadlineExceeded}, true},
		{"an answer of 502", &pullStatusError{url: closed, status: http.StatusBadGateway}, false},
		{"an answer of 500 as text", errors.New("HTTP 500"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isAgentTransportFailure(tc.err); got != tc.want {
				t.Errorf("isAgentTransportFailure(%v) = %t, want %t", tc.err, got, tc.want)
			}
		})
	}
}
