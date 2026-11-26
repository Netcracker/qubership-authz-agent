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

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/gofiber/fiber/v2"

	"authz-agent/components/authz-agent/internal/legacy"
	"authz-agent/components/authz-agent/internal/snapshot"
	"authz-agent/internal/regogen"
)

// tenantHeader names the tenant of a request that has no query parameter
// tenant_id.
const tenantHeader = "Tenant"

// decide answers a check/resource request, single or bulk, with the
// generated policies of the request's tenant and writes the response in the
// shape of the route. The embedded policies check the caller and the
// subject's token first: a refused admission token is answered with its
// authError, and a refused subject token denies every item with its reason.
// Without a registry, and for a request of the default tenant while its name
// is not resolved, every item is denied as in a tenant without policies.
func (s *Server) decide(c *fiber.Ctx, resources []legacy.Resource, shape func(result any) []byte) error {
	input, admission, unresolved, answered := s.admit(c)
	if answered != nil {
		return answered()
	}
	ctx := c.UserContext()
	tenant := input["tenant"].(string)
	var results []snapshot.Result
	switch reason, refused := admission["subjectError"]; {
	case refused:
		results = make([]snapshot.Result, len(resources))
		for i := range results {
			results[i].Reason = fmt.Sprint(reason)
		}
	case s.opts.Snapshots == nil || unresolved:
		results = make([]snapshot.Result, len(resources))
		for i := range results {
			results[i].Reason = fmt.Sprintf(snapshot.ReasonNoTenant, tenant)
		}
	default:
		sub, err := subject(c, tenant, admission)
		var req snapshot.Request
		if err == nil {
			req, err = snapshot.NewRequest(sub, resources)
		}
		if err != nil {
			s.opts.Log.DebugC(ctx, "legacy request rejected path=%s: %v", c.Path(), err)
			return c.Status(http.StatusBadRequest).JSON(fiber.Map{"message": "bad request"})
		}
		if results, err = s.opts.Snapshots.Decide(ctx, req); err != nil {
			s.opts.Log.ErrorC(ctx, "decision failed tenant=%s: %v", tenant, err)
			return opaError(c, http.StatusInternalServerError, "internal_error", err.Error())
		}
	}
	result := legacyResult(resources, results)
	s.log(c, input)
	return sendJSON(c, http.StatusOK, shape(result))
}

// filter answers a check/filter request with the generated filter of the
// request's tenant, after the same checks of the caller and the subject's
// token as decide: a refused subject token, a service without a registry,
// and a request of the default tenant while its name is not resolved get
// DENY.
func (s *Server) filter(c *fiber.Ctx, r legacy.Resource) error {
	input, admission, unresolved, answered := s.admit(c)
	if answered != nil {
		return answered()
	}
	ctx := c.UserContext()
	tenant := input["tenant"].(string)
	answer := regogen.FilterAnswer{Result: regogen.FilterDeny}
	if _, refused := admission["subjectError"]; !refused && s.opts.Snapshots != nil && !unresolved {
		sub, err := subject(c, tenant, admission)
		if err != nil {
			s.opts.Log.DebugC(ctx, "legacy request rejected path=%s: %v", c.Path(), err)
			return c.Status(http.StatusBadRequest).JSON(fiber.Map{"message": "bad request"})
		}
		if answer, err = s.opts.Snapshots.Filter(ctx, snapshot.NewFilterRequest(sub, r)); err != nil {
			s.opts.Log.ErrorC(ctx, "filter failed tenant=%s: %v", tenant, err)
			return opaError(c, http.StatusInternalServerError, "internal_error", err.Error())
		}
	}
	body, err := json.Marshal(answer)
	if err != nil {
		return opaError(c, http.StatusInternalServerError, "internal_error", err.Error())
	}
	s.log(c, input)
	return sendJSON(c, http.StatusOK, body)
}

// admit builds the input of the embedded policies, with the tenant of the
// request, and evaluates their checks of the caller and the
// subject's token. unresolved reports what [Server.tenant] reports.
// answered is non-nil when the request is answered already: a refused
// admission token, with its authError; a caller outside its tenant
// ([callerMayReach]), with 403 and an empty body; or a failed evaluation,
// with 500.
func (s *Server) admit(c *fiber.Ctx) (input, admission map[string]any,
	unresolved bool, answered func() error) {
	ctx := c.UserContext()
	input = legacy.Input(c.GetReqHeaders())
	admission, err := s.admission(ctx, input)
	if err != nil {
		s.opts.Log.ErrorC(ctx, "admission failed: %v", err)
		return nil, nil, false, func() error { return opaError(c, http.StatusInternalServerError, "internal_error", err.Error()) }
	}
	tenant, unresolved := s.tenant(c)
	input["tenant"] = tenant
	if raw, refused := admission["authError"]; refused {
		s.log(c, input)
		status, body, _ := legacy.AuthError(map[string]any{"authError": raw})
		return nil, nil, false, func() error { return sendJSON(c, status, body) }
	}
	if claims, ok := admission["callerClaims"].(map[string]any); ok && !callerMayReach(claims, tenant, s.resolvedDefaultTenant()) {
		s.opts.Log.DebugC(ctx, "caller refused path=%s tenant=%s reason=CALLER_TENANT_MISMATCH", c.Path(), tenant)
		return nil, nil, false, func() error {
			c.Status(http.StatusForbidden)
			return nil
		}
	}
	return input, admission, unresolved, nil
}

// callerMayReach reports whether the caller whose verified token carries
// claims may ask about tenant. An M2M token ([m2mToken]) may name any tenant.
// Any other token may name only the tenant of its tenant-id claim, compared
// byte for byte, or the default tenant when the claim is absent, null, or
// empty; a claim that is not a string matches no tenant.
func callerMayReach(claims map[string]any, tenant, defaultTenant string) bool {
	if m2mToken(claims) {
		return true
	}
	switch claim := claims["tenant-id"].(type) {
	case nil:
		return tenant == defaultTenant
	case string:
		if claim == "" {
			return tenant == defaultTenant
		}
		return claim == tenant
	default:
		return false
	}
}

// m2mToken reports whether a token with claims is an M2M token: its
// realm_access.roles holds ROLE_M2M, compared byte for byte, or its level is
// m2m or key-manager, compared without regard to case.
func m2mToken(claims map[string]any) bool {
	if level, ok := claims["level"].(string); ok && (strings.EqualFold(level, "m2m") || strings.EqualFold(level, "key-manager")) {
		return true
	}
	access, _ := claims["realm_access"].(map[string]any)
	roles, _ := access["roles"].([]any)
	for _, r := range roles {
		if r == "ROLE_M2M" {
			return true
		}
	}
	return false
}

// defaultTenant is the default tenant, or "" without one.
func (s *Server) defaultTenant() string {
	if s.opts.DefaultTenant != nil {
		return s.opts.DefaultTenant()
	}
	return ""
}

// resolvedDefaultTenant is the ID of the default tenant, or "" while it is
// not resolved or without one, so that a request is never compared with the
// display name.
func (s *Server) resolvedDefaultTenant() string {
	if s.opts.DefaultTenantResolved != nil && !s.opts.DefaultTenantResolved() {
		return ""
	}
	return s.defaultTenant()
}

// log reports a decision at debug. The line carries the tenant and no part
// of the input, which holds the caller's token and claims.
func (s *Server) log(c *fiber.Ctx, input map[string]any) {
	s.opts.Log.DebugC(c.UserContext(), "decision path=authorize tenant=%v", input["tenant"])
}

// admission evaluates the caller and subject checks of the embedded
// policies on input.
func (s *Server) admission(ctx context.Context, input map[string]any) (map[string]any, error) {
	v, defined, err := s.engine.Eval(ctx, []string{"authorize_internals", "admission"}, input)
	if err != nil {
		return nil, err
	}
	m, ok := v.(map[string]any)
	if !defined || !ok {
		return nil, fmt.Errorf("the embedded policies gave no admission outcome")
	}
	return m, nil
}

// tenant is the tenant a request is decided in: the query parameter
// tenant_id, else the header Tenant, else the default tenant. An empty
// source is skipped; any other value is the tenant as received, so a query
// parameter with a space around the name is another tenant than the name.
// HTTP strips the spaces around a header value before it gets here.
//
// unresolved reports that the tenant is the default tenant and tenant-manager
// had not resolved its name to an ID when the request arrived, so the tenant
// is a name whose policy data, if any, is another tenant's. The flag is read
// before the tenant, so a resolution in between leaves it set.
func (s *Server) tenant(c *fiber.Ctx) (tenant string, unresolved bool) {
	if t := lastQuery(c, "tenant_id"); t != "" {
		return t, false
	}
	if t := c.Get(tenantHeader); t != "" {
		return t, false
	}
	unresolved = s.opts.DefaultTenantResolved != nil && !s.opts.DefaultTenantResolved()
	return s.defaultTenant(), unresolved
}

// subject is the [snapshot.Subject] of the admitted request c in tenant,
// with the token payload of its admission.
func subject(c *fiber.Ctx, tenant string, admission map[string]any) (snapshot.Subject, error) {
	return snapshot.NewSubject(tenant, c.GetReqHeaders(), admission["tokenPayload"])
}

// legacyResult is the decision in the shape the response builders of
// package legacy read: results with resourceType, operation, isAllowed, and
// the reason of a denial.
func legacyResult(resources []legacy.Resource, results []snapshot.Result) map[string]any {
	list := make([]any, len(results))
	for i, r := range results {
		item := map[string]any{
			"resourceType": resources[i].ResourceType,
			"operation":    resources[i].Operation,
			"isAllowed":    r.Allowed,
		}
		if !r.Allowed {
			item["reason"] = r.Reason
		}
		list[i] = item
	}
	return map[string]any{"rlsIgnored": false, "results": list}
}
