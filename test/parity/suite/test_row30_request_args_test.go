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
	"net/http"

	"authz-agent/test/parity/suite/model"
)

// Row 30 — GENERAL (HTTP) PIP request-args & contract extension
// (authz-agent-ADR-0066..0069). These are NOT legacy-parity golden cases: they
// exercise the NEW request-args contract that access-control has no equivalent
// for (substitution into query/headers/body, response.extract, per-request
// timeout, x-request-id correlation, operand-local failure isolation). They
// assert behaviour directly (decision + GET /pip-stub/calls) against the static
// PIP_STUB_CONFIG rules under /api/v1/pip/ra/*, so no golden files are involved.
//
// Fixtures: testdata/fixtures/policies/suite/requestargs-pips.json (+ -rls.json).

// findPipCall returns the first recorded pip-stub call to the given path.
func findPipCall(calls []PipStubCall, path string) (PipStubCall, bool) {
	for _, c := range calls {
		if c.Path == path {
			return c, true
		}
	}
	return PipStubCall{}, false
}

// §C — substitution into query / headers / body reaches the wire, incl. embedded
// templates (customer-${resource.id}); §G — an inbound x-request-id is propagated
// onto the PIP call.
func (s *ParitySuite) TestRow30RequestArgsEchoSubstitution() {
	ctx := context.Background()
	s.Require().NoError(s.pipMock.ResetCalls(ctx))

	status, decision, _, err := HelperCheckResourceV1(ctx, s.cfg,
		model.CheckAccessRequest{Operation: "READ", Type: "PARITY_RA_ECHO", Resource: map[string]any{"id": "ECHO-42"}},
		s.mustTokenBundle(UserProfileReader),
		PerCallOptions{CustomHeaders: map[string]string{"x-request-id": "R-ECHO-1"}},
	)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusOK, status)
	s.True(decision, "echo pip resolves method=POST → policy allows")

	calls, err := s.pipMock.GetCalls(ctx)
	s.Require().NoError(err)
	call, ok := findPipCall(calls, "/api/v1/pip/ra/echo")
	s.Require().True(ok, "echo pip must have been called")
	s.Equal(http.MethodPost, call.Method)
	s.Equal([]string{"ECHO-42"}, call.Query["rid"], "query ${resource.id} substituted")
	s.Equal("trace-ECHO-42", call.Headers["x-trace-id"], "embedded header template substituted")
	s.Equal("R-ECHO-1", call.Headers["x-request-id"], "inbound x-request-id propagated to the PIP call")
	if body, ok := call.Body.(map[string]any); s.True(ok, "echo body parsed as object") {
		s.Equal("ECHO-42", body["receivedId"], "body ${resource.id} substituted")
		s.Equal("customer-ECHO-42", body["label"], "embedded body template substituted")
	}
}

// §G — with no inbound x-request-id, OPA generates one and it still lands on the
// PIP call (Envoy also supplies one on this path; either way it is present).
func (s *ParitySuite) TestRow30RequestArgsRequestIdPresentWhenAbsent() {
	ctx := context.Background()
	s.Require().NoError(s.pipMock.ResetCalls(ctx))

	_, decision, _, err := HelperCheckResourceV1(ctx, s.cfg,
		model.CheckAccessRequest{Operation: "READ", Type: "PARITY_RA_ECHO", Resource: map[string]any{"id": "GEN-1"}},
		s.mustTokenBundle(UserProfileReader),
		PerCallOptions{},
	)
	s.Require().NoError(err)
	s.True(decision)

	calls, err := s.pipMock.GetCalls(ctx)
	s.Require().NoError(err)
	call, ok := findPipCall(calls, "/api/v1/pip/ra/echo")
	s.Require().True(ok)
	s.NotEmpty(call.Headers["x-request-id"], "a correlation id is present on the PIP call even without an inbound one")
}

// §C — response.extract=$.data.ids[*].id binds a whole-value array; a policy IN
// predicate admits/denies against it.
func (s *ParitySuite) TestRow30RequestArgsWholeValueArrayIN() {
	ctx := context.Background()

	_, allow, _, err := HelperCheckResourceV1(ctx, s.cfg,
		model.CheckAccessRequest{Operation: "READ", Type: "PARITY_RA_ALLOWED", Resource: map[string]any{"id": "C1"}},
		s.mustTokenBundle(UserProfileReader), PerCallOptions{})
	s.Require().NoError(err)
	s.True(allow, "C1 ∈ [C1,C2,C3] → allow")

	_, deny, _, err := HelperCheckResourceV1(ctx, s.cfg,
		model.CheckAccessRequest{Operation: "READ", Type: "PARITY_RA_ALLOWED", Resource: map[string]any{"id": "Z9"}},
		s.mustTokenBundle(UserProfileReader), PerCallOptions{})
	s.Require().NoError(err)
	s.False(deny, "Z9 ∉ [C1,C2,C3] → deny")
}

// §E — per-request timeoutSeconds:1 against a delayMs:3000 upstream. http.send
// times out; raise_error:false + defaultValue rescues the alias so the decision
// proceeds on the default. Asserts the stub WAS called (a real timeout, not a
// skipped call) and that the default set — not a blanket allow — drives the match.
func (s *ParitySuite) TestRow30RequestArgsTimeoutUsesDefault() {
	ctx := context.Background()
	s.Require().NoError(s.pipMock.ResetCalls(ctx))

	_, allow, _, err := HelperCheckResourceV1(ctx, s.cfg,
		model.CheckAccessRequest{Operation: "READ", Type: "PARITY_RA_TIMEOUT", Resource: map[string]any{"id": "TIMEOUT-DEFAULT"}},
		s.mustTokenBundle(UserProfileReader), PerCallOptions{})
	s.Require().NoError(err)
	s.True(allow, "alias resolves to defaultValue [TIMEOUT-DEFAULT] on timeout → id ∈ default → allow")

	_, deny, _, err := HelperCheckResourceV1(ctx, s.cfg,
		model.CheckAccessRequest{Operation: "READ", Type: "PARITY_RA_TIMEOUT", Resource: map[string]any{"id": "OTHER"}},
		s.mustTokenBundle(UserProfileReader), PerCallOptions{})
	s.Require().NoError(err)
	s.False(deny, "OTHER ∉ default set → deny (proves the real default drives the decision, not a blanket allow)")

	calls, err := s.pipMock.GetCalls(ctx)
	s.Require().NoError(err)
	_, ok := findPipCall(calls, "/api/v1/pip/ra/slow")
	s.True(ok, "slow pip WAS called (timeout with a response, not a skipped call)")
}

// §D — operand-local failure isolation + negation fail-closed. subject.raBrokenId
// is a hard-failing GENERAL PIP (500, onMissing:error → alias absent). The rule
// `subject.raBrokenId != 'sentinel' OR resource.ok == true` must:
//   - allow when resource.ok == true (the OR sibling grants; the broken-PIP
//     operand does not abort the decision — isolation), and
//   - deny when resource.ok == false (the neq over a failed PIP must NOT fail
//     open; the branch is genuinely false).
func (s *ParitySuite) TestRow30RequestArgsNegationFailClosed() {
	ctx := context.Background()

	_, allow, _, err := HelperCheckResourceV1(ctx, s.cfg,
		model.CheckAccessRequest{Operation: "READ", Type: "PARITY_RA_NEG", Resource: map[string]any{"ok": true}},
		s.mustTokenBundle(UserProfileReader), PerCallOptions{})
	s.Require().NoError(err)
	s.True(allow, "OR sibling grants despite the broken-PIP negation operand (operand-local isolation)")

	_, deny, _, err := HelperCheckResourceV1(ctx, s.cfg,
		model.CheckAccessRequest{Operation: "READ", Type: "PARITY_RA_NEG", Resource: map[string]any{"ok": false}},
		s.mustTokenBundle(UserProfileReader), PerCallOptions{})
	s.Require().NoError(err)
	s.False(deny, "neq over a failed PIP must NOT grant — fail-closed (no accidental allow)")
}
