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

//go:build paritytest

package server

import (
	"context"
	"errors"
	"net/http"
	"sync/atomic"
	"testing"
)

func TestPullRoute_AnswersNoContentOnceThePoliciesAreStored(t *testing.T) {
	var calls atomic.Int32
	internal, _ := pullServer(t, func(context.Context) error { calls.Add(1); return nil })

	code, _, raw := do(t, internal, http.MethodPost, "/internal/v1/pull", "", nil)

	if code != http.StatusNoContent {
		t.Errorf("POST /internal/v1/pull = %d %s, want 204", code, raw)
	}
	if n := calls.Load(); n != 1 {
		t.Errorf("PullNow calls = %d, want 1", n)
	}
}

func TestPullRoute_ReportsAFailedLoadAsBadGateway(t *testing.T) {
	internal, _ := pullServer(t, func(context.Context) error { return errors.New("fetch policySets: HTTP 500") })

	code, body, raw := do(t, internal, http.MethodPost, "/internal/v1/pull", "", nil)

	if code != http.StatusBadGateway || body["error"] != "fetch policySets: HTTP 500" {
		t.Errorf("POST /internal/v1/pull = %d %s, want 502 with the error of the load", code, raw)
	}
}

func TestPullRoute_IsNotOnThePublicSurface(t *testing.T) {
	var calls atomic.Int32
	_, public := pullServer(t, func(context.Context) error { calls.Add(1); return nil })

	code, _, raw := do(t, public, http.MethodPost, "/internal/v1/pull", "", nil)

	if code != http.StatusNotFound {
		t.Errorf("public POST /internal/v1/pull = %d %s, want 404", code, raw)
	}
	if n := calls.Load(); n != 0 {
		t.Errorf("PullNow calls = %d, want 0", n)
	}
}

func TestPullRoute_IsNotAddedWithoutPullNow(t *testing.T) {
	internal, _ := pullServer(t, nil)

	code, _, raw := do(t, internal, http.MethodPost, "/internal/v1/pull", "", nil)

	if code != http.StatusNotFound {
		t.Errorf("POST /internal/v1/pull = %d %s, want 404", code, raw)
	}
}
