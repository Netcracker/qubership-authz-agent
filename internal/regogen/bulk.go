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

package regogen

import (
	"sync"

	"github.com/open-policy-agent/opa/v1/ast"

	"authz-agent/internal/jsonvalue"
	"authz-agent/internal/regobuiltins"
	"authz-agent/internal/regogen/spectables"
)

// Bulk is the projection of what the items of a bulk request share: the
// subject, the PIPs, the permission scope, and the subject groups. Each item
// adds its operation, its resource type, and the operands of its resource
// ([Bulk.Item]). A Bulk is safe for concurrent use once built.
type Bulk struct {
	in *Input
	// items holds the references each item resolves from its body.
	items []*Ref
	// fields holds the maps of [fieldMaps] over the shared records, and top
	// the members folded_roles, m2m, subject_groups, scope_passes, and
	// scope_failed of the input.
	fields map[string]*ast.Term
	top    [][2]*ast.Term
	// m and req are the module and the shared request, which the calls of
	// its GENERAL and FILTERED PIPs read with each item's body.
	m   *Module
	req Request
	// views holds the [resourceView] of each resource an item has carried,
	// by [identity]; mu guards it.
	mu    sync.Mutex
	views map[any]*resourceView
}

// resourceView is what the items of a bulk request derive from one decoded
// resource: the records of the resource operands, the term of the member
// resource, the records of the lazily read paths, and the requests of the
// GENERAL and FILTERED PIPs and of the entitlements service. The items whose
// bodies carry the same decoded value share one view, so what it holds is
// derived once per request, not once per item.
type resourceView struct {
	resource jsonvalue.Value
	// records holds the record of each resource operand of [Bulk.items] by
	// reference ID; err is the first error a record or a path of an index
	// gave, which fails every item that carries the resource.
	records map[string]Record
	err     error
	// term is the member resource, which [resourceView.memberTerm] builds in
	// docs at the first item evaluated, on that item's worker.
	termOnce sync.Once
	term     *ast.Term
	docs     *regobuiltins.Documents
	// paths holds the record of each lazily read path, those of an index
	// built with the view and the rest as nc.resource_path asks for them;
	// pathsMu guards it, since the items are evaluated concurrently.
	pathsMu sync.Mutex
	paths   map[pathKey]*ast.Term
	// calls and pipValues are the [Input] members of the same names, which
	// [resourceView.setCalls] builds at the first item that carries the
	// resource.
	callsOnce sync.Once
	calls     ast.Object
	pipValues map[string]Resolved
}

// listKey identifies a non-empty list by its first element and length.
type listKey struct {
	first *jsonvalue.Value
	n     int
}

// identity returns a key that two decoded values share only where they are
// the same value in memory, and ok false for a scalar or an empty list,
// whose records cost no more than the lookup.
func identity(v jsonvalue.Value) (key any, ok bool) {
	switch x := v.(type) {
	case *jsonvalue.Object:
		return x, true
	case []jsonvalue.Value:
		if len(x) > 0 {
			return listKey{&x[0], len(x)}, true
		}
	}
	return nil, false
}

// view returns the view of res, built at its first item, or nil where res
// has no [identity].
func (b *Bulk) view(res jsonvalue.Value) *resourceView {
	key, ok := identity(res)
	if !ok {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if v, ok := b.views[key]; ok {
		return v
	}
	v := b.newView(res)
	if b.views == nil {
		b.views = map[any]*resourceView{}
	}
	b.views[key] = v
	return v
}

func (b *Bulk) newView(res jsonvalue.Value) *resourceView {
	v := &resourceView{resource: res, docs: regobuiltins.NewDocuments(), records: map[string]Record{}}
	probe := &Input{resource: res, refs: b.in.refs}
	if v.err = probe.checkPaths(); v.err != nil {
		return v
	}
	v.paths = probe.paths
	if v.paths == nil {
		v.paths = map[pathKey]*ast.Term{}
	}
	body := Body{Resource: res, HasResource: true}
	for _, r := range b.items {
		if r.Kind == spectables.KindOperation || r.Kind == spectables.KindResourceType {
			continue
		}
		rec, err := projectRecord(r, body.resolve(r))
		if err != nil {
			v.err = err
			return v
		}
		v.records[r.ID] = rec
	}
	return v
}

// memberTerm returns the term of the view's resource. Every item reads its
// docs only after this call, so no query reads them while they are built.
func (v *resourceView) memberTerm() *ast.Term {
	v.termOnce.Do(func() {
		// a jsonvalue.Value always has a term
		v.term, _ = v.docs.Term(v.resource)
	})
	return v.term
}

// path returns the record of the lazily read path p of the view's resource
// as read reads it, built at its first call.
func (v *resourceView) path(p string, read fieldSet) (*ast.Term, error) {
	v.pathsMu.Lock()
	defer v.pathsMu.Unlock()
	k := pathKey{p, read}
	if r, ok := v.paths[k]; ok {
		return r, nil
	}
	r, err := jsonPathRecord(v.resource, p, read)
	if err == nil {
		v.paths[k] = r
	}
	return r, err
}

// setCalls sets the requests of the PIPs of in, the input of an item that
// carries the view's resource, to those of the view. A request reads the
// subject, which b.req holds, and the resource, and no other part of the
// item's body, so the view builds them from a body that holds the resource
// alone.
func (v *resourceView) setCalls(b *Bulk, in *Input) {
	v.callsOnce.Do(func() {
		req := b.req
		req.Body = Body{Resource: v.resource, HasResource: true}
		own := &Input{}
		// NewBulk checked the values setCalls requires
		_ = own.setCalls(b.m, &req)
		v.calls, v.pipValues = own.calls, own.pipValues
	})
	in.calls, in.pipValues = v.calls, v.pipValues
}

// itemOperand reports whether each item of a bulk request resolves r from
// its own body.
func itemOperand(r *Ref) bool {
	return r.Kind == spectables.KindOperation || r.Kind == spectables.KindResourceType || resourceOperand(r)
}

// NewBulk projects the part of a bulk request that its items share. req
// holds the resolved value of each operand the module reads that is not the
// operation, the resource type, or an operand of the resource; its Body is
// not read. NewBulk fails as [Project] does on a missing value.
func NewBulk(m *Module, req Request) (*Bulk, error) {
	shared := req
	shared.Body = Body{}
	values := make(map[string]Resolved, len(req.Values))
	for k, v := range req.Values {
		values[k] = v
	}
	b := &Bulk{}
	for _, r := range m.Refs {
		if !r.Pass && r.Path == "" && itemOperand(r) {
			b.items = append(b.items, r)
			// a placeholder Project reads in place of the item's value, dropped below
			values[r.Key] = Resolved{State: spectables.StateAbsent}
		}
	}
	shared.Values = values
	in, err := Project(m, shared)
	if err != nil {
		return nil, err
	}
	for _, r := range b.items {
		delete(in.Records, r.ID)
	}
	b.in, b.m, b.req = in, m, shared
	b.fields = make(map[string]*ast.Term, len(recordFields))
	for f, o := range fieldObjects(m.Refs, func(r *Ref) (Record, bool) {
		rec, ok := in.Records[r.ID]
		return rec, ok && !r.Network && !r.Pass
	}) {
		b.fields[f] = ast.NewTerm(o)
	}
	b.top = in.subjectMembers()
	return b, nil
}

// Item returns the input of one item of the bulk request, whose body is
// body. The input shares the subject's part with every other item: its
// Records hold the item's records only, and its Value reuses the shared
// terms. The items whose bodies carry the same decoded resource share what
// is derived from it ([resourceView]), the requests of the PIPs included. It fails where a value of
// the item other than the answer of a source is too big to compare
// ([Record.TooBig]).
func (b *Bulk) Item(body Body) (*Input, error) {
	in := &Input{
		Records:       make(map[string]Record, len(b.items)),
		FoldedRoles:   b.in.FoldedRoles,
		M2M:           b.in.M2M,
		SubjectGroups: b.in.SubjectGroups,
		Passes:        b.in.Passes,
		ScopeFailed:   b.in.ScopeFailed,
		refs:          b.in.refs,
		docs:          regobuiltins.NewDocuments(),
		bulk:          b,
	}
	if body.HasResource {
		in.resource = body.Resource
		if in.view = b.view(body.Resource); in.view != nil {
			if in.view.err != nil {
				return nil, in.view.err
			}
			in.docs = in.view.docs
		} else if err := in.checkPaths(); err != nil {
			return nil, err
		}
	}
	for _, r := range b.items {
		var v Resolved
		switch r.Kind {
		case spectables.KindOperation:
			v = Resolved{State: spectables.StateValue, Value: body.Operation}
		case spectables.KindResourceType:
			v = Resolved{State: spectables.StateValue, Value: body.ResourceType}
		default:
			if in.view != nil {
				in.Records[r.ID] = in.view.records[r.ID]
				continue
			}
			v = body.resolve(r)
		}
		rec, err := projectRecord(r, v)
		if err != nil {
			return nil, err
		}
		in.Records[r.ID] = rec
	}
	if in.view != nil {
		in.view.setCalls(b, in)
		return in, nil
	}
	req := b.req
	req.Body = body
	// NewBulk checked the values setCalls requires
	_ = in.setCalls(b.m, &req)
	return in, nil
}

// value is the [Input.Value] of the item in: each map of a field joins the
// shared entries and the item's, and a map the item adds nothing to is the
// shared term itself.
func (b *Bulk) value(in *Input) ast.Value {
	type entry struct{ id, v *ast.Term }
	own := map[string][]entry{}
	for _, r := range b.items {
		id := strTerm(r.ID)
		in.Records[r.ID].fields(r.emit, func(f string, v *ast.Term) { own[f] = append(own[f], entry{id, v}) })
	}
	o := ast.NewObjectWithCapacity(len(recordFields) + len(b.top) + 1)
	for _, f := range recordFields {
		t := b.fields[f]
		if add := own[f]; len(add) > 0 {
			shared := t.Value.(ast.Object)
			j := ast.NewObjectWithCapacity(shared.Len() + len(add))
			shared.Foreach(j.Insert)
			for _, e := range add {
				j.Insert(e.id, e.v)
			}
			t = ast.NewTerm(j)
		}
		o.Insert(strTerm(f), t)
	}
	for _, kv := range b.top {
		o.Insert(kv[0], kv[1])
	}
	if in.calls != nil {
		o.Insert(strTerm(memberPIPRequests), ast.NewTerm(in.calls))
	}
	if b.in.resourceMember() {
		res := ast.NullTerm()
		switch {
		case in.view != nil:
			res = in.view.memberTerm()
		case in.resource != nil:
			// a jsonvalue.Value always has a term
			res, _ = in.docs.Term(in.resource)
		}
		o.Insert(strTerm(memberResource), res)
	}
	return o
}
