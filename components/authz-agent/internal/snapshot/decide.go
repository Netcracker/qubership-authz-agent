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
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/open-policy-agent/opa/v1/rego"

	"authz-agent/components/authz-agent/internal/panics"
	"authz-agent/internal/regobuiltins"
	"authz-agent/internal/regogen"
)

// Request is one check request: the [Subject] and one item per resource
// and operation, in the order of the answers.
type Request struct {
	Subject
	Items []regogen.Body
}

// Result is the answer for one item. Reason says why an item is denied.
type Result struct {
	Allowed bool
	Reason  string
}

// Reasons of a denial.
const (
	// ReasonNoTenant denies every item of a tenant without a published
	// snapshot.
	ReasonNoTenant = "no policies are published for tenant %s"
	// ReasonDenied denies an item that no policy allows.
	ReasonDenied = "no policy of the tenant allows the operation on the resource"
	// ReasonUnknown prefixes a denial that depends on a value the agent
	// could not read or that failed a comparison, such as IS EMPTY over a
	// null PIP body.
	ReasonUnknown = "PIP resolution failed"
)

// Decide answers each item of req with the snapshot of req.Tenant. A
// tenant without one denies every item. A GENERAL or FILTERED PIP the
// items read is called once per distinct request across all items. The
// error is not a denial. An error that wraps a badrequest.Error fails the
// whole request because a value the request carries, of the subject or of
// one item, is too big to compare. Any other error is a failure of the
// agent: a defect of the projection or the evaluation, or of the tenant's
// configuration, such as a permission too big to compare that its mapping
// tables grant.
func (r *Registry) Decide(ctx context.Context, req Request) ([]Result, error) {
	out := make([]Result, len(req.Items))
	s, ok := r.Snapshot(req.Tenant)
	if !ok {
		for i := range out {
			out[i].Reason = fmt.Sprintf(ReasonNoTenant, req.Tenant)
		}
		return out, nil
	}
	m := s.Module
	base, unread, ctx := r.prepare(ctx, m, req.Subject)
	var inputs []*regogen.Input
	if len(req.Items) == 1 {
		one := base
		one.Body = req.Items[0]
		one.Values = maps.Clone(base.Values)
		m.Resolve(one.Body, one.Values)
		in, err := regogen.Project(m, one)
		if err != nil {
			return nil, fmt.Errorf("tenant %s: project the request: %w", req.Tenant, err)
		}
		inputs = []*regogen.Input{in}
	} else if len(req.Items) > 1 {
		bulk, err := regogen.NewBulk(m, base)
		if err != nil {
			return nil, fmt.Errorf("tenant %s: project the bulk request: %w", req.Tenant, err)
		}
		inputs = make([]*regogen.Input, len(req.Items))
		for i, b := range req.Items {
			if inputs[i], err = bulk.Item(b); err != nil {
				return nil, fmt.Errorf("tenant %s: project item %d of the bulk request: %w", req.Tenant, i, err)
			}
		}
	}
	errs := make([]error, len(inputs))
	if len(inputs) <= 1 || r.cfg.BulkWorkers <= 1 {
		for i := range inputs {
			out[i], errs[i] = r.evalItem(ctx, s, inputs[i], unread)
		}
	} else {
		// A panic on a worker would end the process, so the worker keeps it,
		// with the worker's stack, and Decide raises the [panics.Recovered]
		// again on the caller's goroutine, which the server recovers and
		// reports by the worker's stack alone. The worker also cancels the items still being
		// evaluated: a call of a PIP it made is never answered, and the
		// workers waiting for it stop at the cancellation.
		wctx, cancel := context.WithCancel(ctx)
		defer cancel()
		next := make(chan int)
		var wg sync.WaitGroup
		var panicked atomic.Pointer[panics.Recovered]
		for range min(r.cfg.BulkWorkers, len(inputs)) {
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer func() {
					if p := recover(); p != nil {
						panicked.CompareAndSwap(nil, panics.Catch(p))
						cancel()
						for range next {
							// drained, so that the feeding loop is not blocked
						}
					}
				}()
				for i := range next {
					out[i], errs[i] = r.evalItem(wctx, s, inputs[i], unread)
				}
			}()
		}
		for i := range inputs {
			next <- i
		}
		close(next)
		wg.Wait()
		if p := panicked.Load(); p != nil {
			panic(p)
		}
	}
	for _, err := range errs {
		if err != nil {
			return nil, fmt.Errorf("tenant %s: %w", req.Tenant, err)
		}
	}
	return out, nil
}

// evalItem evaluates the rule allow for one input and, for a denial, the rule
// maybe, which tells a denial that rests on an unread value from a plain one.
// maybe is a rule of the decision module.
func (r *Registry) evalItem(ctx context.Context, s *Snapshot, in *regogen.Input, unread []string) (Result, error) {
	ictx := in.Context(ctx)
	v := in.Value()
	rs, err := s.q.allow.Eval(ictx, rego.EvalParsedInput(v))
	if err != nil {
		return Result{}, fmt.Errorf("evaluate allow: %w", err)
	}
	if len(rs) == 1 && rs[0].Expressions[0].Value == true {
		return Result{Allowed: true}, nil
	}
	rs, err = s.q.maybe.Eval(ictx, rego.EvalParsedInput(v))
	if err != nil {
		return Result{}, fmt.Errorf("evaluate maybe: %w", err)
	}
	if len(rs) == 1 && rs[0].Expressions[0].Value == true {
		return Result{Reason: unknownReason(ctx, s, unread)}, nil
	}
	return Result{Reason: ReasonDenied}, nil
}

// unknownReason names the sources a denial may rest on: the PIPs whose call
// failed in this decision request, the parts of the snapshot that fail
// permanently, and the operands that failed for want of a source: no
// entitlements URL, no PERMISSION_SCOPE PIP, or a failed read of the scope. The items of a
// bulk request share their calls, so a PIP that failed for one item is named
// in the reason of every item denied on an unknown operand.
func unknownReason(ctx context.Context, s *Snapshot, unread []string) string {
	var names []string
	names = append(names, regobuiltins.FailedPIPs(ctx)...)
	for _, f := range s.Module.Failures {
		switch {
		case f.PIP != "":
			names = append(names, f.PIP)
		case f.Policy != "":
			names = append(names, "policy "+f.Policy)
		case f.Set != "":
			names = append(names, "set "+f.Set)
		}
	}
	names = append(names, unread...)
	slices.Sort(names)
	names = slices.Compact(names)
	if len(names) == 0 {
		return ReasonUnknown
	}
	return ReasonUnknown + ": " + strings.Join(names, ", ")
}
