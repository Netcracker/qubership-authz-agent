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

package snapshot

import (
	"context"
	"encoding/json"
	"fmt"

	"authz-agent/components/authz-agent/internal/legacy"
	"authz-agent/internal/jsonvalue"
	"authz-agent/internal/regobuiltins"
	"authz-agent/internal/regogen"
)

// Subject is what a check request and a check/filter request share: the
// tenant the request is decided in, the claims and the anonymity the
// subject is read from, and the parts of the HTTP request that the PIPs
// receive.
type Subject struct {
	Tenant string
	// Claims are the verified claims the subject is read from: those of
	// the subject's token, or of the admission token for an anonymous
	// request; nil for none.
	Claims    *jsonvalue.Object
	Anonymous bool
	// Headers holds the request's headers by lower-case name, the last
	// value of a repeated one.
	Headers map[string]string
	// IncomingToken is the Incoming-Token header as sent, which a PIP
	// receives when its declaration names it; "" for none.
	IncomingToken string
	// RequestID is the id of the decision request, which every call of a
	// PIP carries in X-Request-Id; "" for none.
	RequestID string
}

// NewSubject is the subject of an HTTP request decided in tenant, with the
// request's headers and the token payload that the admission policies
// verified. The request is anonymous when it carries no subject token
// ([legacy.SubjectToken]). Headers are those of [legacy.RequestHeaders], so
// they leave out Authorization and Incoming-Token; the Incoming-Token header
// is kept apart in IncomingToken. A payload that is not a JSON object gives
// empty claims.
func NewSubject(tenant string, headers map[string][]string, payload any) (Subject, error) {
	claims, err := claimsOf(payload)
	if err != nil {
		return Subject{}, err
	}
	return Subject{Tenant: tenant, Claims: claims, Anonymous: legacy.SubjectToken(headers) == "",
		Headers: legacy.RequestHeaders(headers), IncomingToken: legacy.IncomingToken(headers),
		RequestID: legacy.Header(headers, "X-Request-Id")}, nil
}

// NewRequest is the check request of sub with one item per resource, as
// the request wrote it: a field the request left out is null, and a
// resource it left out is absent.
func NewRequest(sub Subject, resources []legacy.Resource) (Request, error) {
	req := Request{Subject: sub, Items: make([]regogen.Body, 0, len(resources))}
	for _, r := range resources {
		b, err := body(r)
		if err != nil {
			return req, err
		}
		req.Items = append(req.Items, b)
	}
	return req, nil
}

// NewFilterRequest is the check/filter request of sub for the resource type
// and the operation of r as the query sent them, an empty operation as none.
func NewFilterRequest(sub Subject, r legacy.Resource) FilterRequest {
	req := FilterRequest{Subject: sub, ResourceType: fmt.Sprint(r.ResourceType)}
	if op := fmt.Sprint(r.Operation); op != "" {
		req.Operation = &op
	}
	return req
}

// claimsOf is payload as claims, an empty object for a payload that is not
// one.
func claimsOf(payload any) (*jsonvalue.Object, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	v, err := jsonvalue.Decode(raw)
	if err != nil {
		return nil, err
	}
	claims, ok := v.(*jsonvalue.Object)
	if !ok {
		claims = jsonvalue.NewObject()
	}
	return claims, nil
}

// body is the item of one resource. The resource is the one r carries,
// which the operations of a bulk/operations item share.
func body(r legacy.Resource) (regogen.Body, error) {
	b := regogen.Body{Resource: r.Resource, HasResource: len(r.Raw.Resource) > 0}
	var err error
	if b.ResourceType, err = decode(r.Raw.Type); err != nil {
		return b, err
	}
	if b.Operation, err = decode(r.Raw.Operation); err != nil {
		return b, err
	}
	return b, nil
}

func decode(raw json.RawMessage) (jsonvalue.Value, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	return jsonvalue.Decode(raw)
}

// prepare is the request of module m for sub before any item: the subject's
// values that m reads, and the permission scope where m iterates over it.
// unread names the sources of the values prepare could not read. The
// context carries the calls of the PIPs that the request shares.
func (r *Registry) prepare(ctx context.Context, m *regogen.Module, sub Subject) (regogen.Request, []string, context.Context) {
	req := regogen.Request{Tenant: sub.Tenant, Anonymous: sub.Anonymous, Claims: sub.Claims, Headers: sub.Headers,
		IncomingToken: sub.IncomingToken, Entitlements: r.cfg.Entitlements}
	claims := sub.Claims
	if claims == nil {
		claims = jsonvalue.NewObject()
	}
	regogen.SubjectOf(claims, sub.Anonymous, regogen.DefaultSubjectRules).Apply(&req)
	unread := m.ResolveSubject(&req)
	ctx = regobuiltins.WithRequestID(regobuiltins.WithCalls(ctx), sub.RequestID)
	if r.cfg.HTTP != nil {
		ctx = r.cfg.HTTP.Context(ctx)
	}
	if m.Iterates {
		req.Scope = m.ReadScope(ctx, &req)
		if req.Scope.Failed {
			unread = append(unread, regogen.ScopePIP)
		}
	}
	return req, unread, ctx
}
