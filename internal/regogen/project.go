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
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/open-policy-agent/opa/v1/ast"

	"authz-agent/internal/jsonvalue"
	"authz-agent/internal/legacyvalue"
	"authz-agent/internal/regobuiltins"
	"authz-agent/internal/regogen/spectables"
)

// Resolved is the value of one operand on a request, as the specification's
// Ctx.resolve gives it: a state and, in state VALUE, the value.
type Resolved struct {
	State spectables.State
	Value jsonvalue.Value
	// PIPList marks a list of several values that a HEADER, GENERAL, or
	// FILTERED PIP builds; it has class pip_list when its elements are
	// scalars.
	PIPList bool
}

// Request is what the projection reads of a check/resource request: the
// body, which gives the operation, the resource type, and the document a
// lazily read resource path reads, and the resolved values of the other
// operands. [Module.Resolve] resolves the operands of the resource.
type Request struct {
	Body  Body
	Roles []string
	M2M   bool
	// Values holds the resolved value of each operand but the operation, the
	// resource type, the pass values, and the lazily read resource paths, by
	// [Ref.Key].
	Values map[string]Resolved
	// Scope is the subject's permission scope that an iterate runs over,
	// read when the module iterates ([Module.Iterates]).
	Scope *Scope
	// Tenant, Anonymous, Claims, and Headers are what the call of a
	// GENERAL or FILTERED PIP reads besides Values and Body: the tenant of
	// the request, which goes into the header Tenant; whether the request
	// names an anonymous subject; the claims of the subject's token, nil
	// for none; and the request's headers by lower-case name, which a
	// declaration forwards and a HEADER placeholder reads.
	Tenant    string
	Anonymous bool
	Claims    *jsonvalue.Object
	Headers   map[string]string
	// Entitlements is the base URL of the entitlements service, which
	// subject.entitledResources calls; empty fails such an operand.
	Entitlements string
}

// Scope is the permission scope of a request's subject as the passes of an
// iterate read it.
type Scope struct {
	// Failed is set when the permission scope cannot be read.
	Failed bool
	// Passes holds, for each assignment of the scope in order, the resolved
	// value of each subject.permissionScope.<key> operand in that pass, by
	// [Ref.Key].
	Passes []map[string]Resolved
	// grants holds each pass's values by scope key, which a placeholder of
	// a filter predicate reads.
	grants []map[string][]jsonvalue.Value
}

// Record is the value record of a reference, as the module reads it.
// ElementKeys, TextKey, EqualityKey, ElementTokens, and ElementTokensWithText
// are set only where the module reads them ([Ref.read]).
type Record struct {
	State       string
	Class       string
	Key         *string
	ElementKeys []string
	Text        *string
	Segments    []string
	// HasNull is set for a list that holds a null element; its keys leave the
	// null out.
	HasNull bool
	// TextKey is the key of the text a string equals a list or an object by
	// (structureText).
	TextKey *string
	// Length is the number of elements of a list, null elements included.
	Length *int
	// EqualityKey is the key two lists are equal by, their typed elements as
	// a set, and the key two objects are equal by, member by member.
	EqualityKey *string
	// ElementTokens and ElementTokensWithText hold the tokens of the
	// elements of a list, or of a value read as a list of one, such that two
	// elements are equal under the collection operators exactly when the
	// ElementTokens of one meets the ElementTokensWithText of the other:
	// ElementTokens holds the token of the element's value (eqToken), and
	// ElementTokensWithText adds, for a list or an object, the token of its
	// text, which a string equals it by.
	ElementTokens, ElementTokensWithText []string
	// Number is the number <, <=, >, and >= compare a string or a scalar by,
	// nil for a value they read as no number.
	Number *jsonvalue.Decimal
	// SubsetLeft holds the tokens of each element of the value read as a
	// list, and SubsetRight those of all its elements, as IS SUBSET compares
	// them on the left and on the right (subsetLeft, subsetRight); set when
	// the module reads them.
	SubsetLeft  [][]string
	SubsetRight []string
}

// Input is the projection of a request into the input of a module.
type Input struct {
	// Records holds the record of each reference by its ID, network PIPs
	// included, pass values and lazy paths not. The input of an item of a
	// bulk request holds the item's own records only ([Bulk.Item]).
	Records       map[string]Record
	FoldedRoles   []string
	M2M           bool
	SubjectGroups []string
	// Passes holds the records of the pass values of each pass, by
	// reference ID; ScopeFailed is [Scope.Failed].
	Passes      []map[string]Record
	ScopeFailed bool
	resource    jsonvalue.Value
	docs        *regobuiltins.Documents
	refs        []*Ref
	// calls holds the q of each GENERAL or FILTERED PIP by reference ID,
	// the member pip_requests of the input; nil for a module without one.
	// pipValues holds the values [Request.Values] gave those PIPs, by
	// reference ID, which [ReplayTransport] answers their calls with.
	calls     ast.Object
	pipValues map[string]Resolved
	// bulk is set on the input of an item of a bulk request, whose Records
	// then hold the item's own records only ([Bulk.Item]).
	bulk *Bulk
}

// class is the class of a value in state VALUE that is not null: the class
// of legacyvalue, with its one class for an object, a nested list, and a list
// with a null element split three ways.
func class(v jsonvalue.Value, lv legacyvalue.Record) spectables.Class {
	switch {
	case lv.State == legacyvalue.StateNullElement:
		return spectables.ClassNullElement
	case lv.State == legacyvalue.StateEmptyColl:
		// the whole resource can be an empty list in state VALUE
		return spectables.ClassList
	case lv.Class == legacyvalue.ClassString:
		return spectables.ClassString
	case lv.Class == legacyvalue.ClassScalar:
		return spectables.ClassScalar
	case lv.Class == legacyvalue.ClassList:
		return spectables.ClassList
	}
	if _, ok := v.(*jsonvalue.Object); ok {
		return spectables.ClassObject
	}
	return spectables.ClassNested
}

func record(r *Ref, v Resolved) Record {
	rec := Record{State: string(v.State)}
	if v.State == spectables.StateSingleOdd {
		// a one-element GENERAL list of null, a boolean, or an object: the
		// collection operators read it as a list
		lv := legacyvalue.OfParts(v.Value, r.parts())
		if r.reads(fieldElementKeys) {
			rec.ElementKeys = lv.Keys
			if rec.ElementKeys == nil {
				rec.ElementKeys = []string{}
			}
		}
		rec.HasNull = lv.State == legacyvalue.StateNullElement
		if r.reads(fieldElementTokens, fieldElementTokensWithText) {
			rec.ElementTokens, rec.ElementTokensWithText = elementTokens(v.Value, lv)
		}
		rec.subset(r, v.Value)
		return rec
	}
	if v.State != spectables.StateValue {
		return rec
	}
	if v.Value == nil {
		rec.Class = string(spectables.ClassNull)
		rec.subset(r, nil)
		return rec
	}
	lv := legacyvalue.OfParts(v.Value, r.parts())
	cl := class(v.Value, lv)
	if cl == spectables.ClassList && v.PIPList {
		cl = spectables.ClassPIPList
	}
	rec.Class = string(cl)
	if r.reads(fieldElementTokens, fieldElementTokensWithText) {
		rec.ElementTokens, rec.ElementTokensWithText = elementTokens(v.Value, lv)
	}
	rec.subset(r, v.Value)
	switch cl {
	case spectables.ClassString, spectables.ClassScalar:
		rec.Key = lv.Key
		if r.reads(fieldElementKeys) {
			rec.ElementKeys = []string{*lv.Key}
		}
		rec.Number = lv.Number
	default:
		if r.reads(fieldElementKeys) {
			rec.ElementKeys = lv.Keys
			if rec.ElementKeys == nil {
				rec.ElementKeys = []string{}
			}
		}
		rec.HasNull = lv.State == legacyvalue.StateNullElement
		switch l, ok := v.Value.([]jsonvalue.Value); {
		case !r.reads(fieldTextKey):
		case ok && len(l) > 0 && allStrings(l):
			// structureText of a list of strings is its Java text, which k
			// folds
			rec.TextKey = lv.Key
		default:
			textKey := legacyvalue.Fold(structureText(v.Value))
			rec.TextKey = &textKey
		}
		if r.reads(fieldEqualityKey) {
			rec.EqualityKey = lv.Structure
		}
		if l, ok := v.Value.([]jsonvalue.Value); ok {
			n := len(l)
			rec.Length = &n
		}
		if lv.State == legacyvalue.StateEmptyColl && r.reads(fieldEqualityKey) {
			// the record of an empty list carries no structure key; it is []
			empty := "[]"
			rec.EqualityKey = &empty
		}
	}
	if s, ok := v.Value.(string); ok {
		rec.Text = &s
		if r.Segments {
			rec.Segments = strings.Split(s, "/")
		}
	}
	return rec
}

// subset sets SubsetLeft and SubsetRight for a reference that IS SUBSET reads.
func (rec *Record) subset(r *Ref, v jsonvalue.Value) {
	if !r.Subset {
		return
	}
	rec.SubsetLeft = subsetLeft(v, inputNumberText)
	rec.SubsetRight = subsetRight(v, inputNumberText, subsetOneValue(r.Kind))
}

// elementTokens returns the ElementTokens and ElementTokensWithText of a
// value, a list or a value read as a list of one; lv is its legacyvalue.Of.
// Where no element is a list or an object, withText is tokens itself.
func elementTokens(v jsonvalue.Value, lv legacyvalue.Record) (tokens, withText []string) {
	l, ok := v.([]jsonvalue.Value)
	elems := lv.Elements
	if !ok {
		l, elems = []jsonvalue.Value{v}, []legacyvalue.Record{lv}
	}
	tokens = []string{}
	for i, e := range l {
		t, ok := "", false
		switch e.(type) {
		case string, jsonvalue.Number, bool:
			// the key of the element's record is the one eqToken reads
			t, ok = "t:"+*elems[i].Key, true
		default:
			t, ok = eqToken(e)
		}
		if ok {
			tokens = append(tokens, t)
			if withText != nil {
				withText = append(withText, t)
			}
		}
		switch e.(type) {
		case []jsonvalue.Value, *jsonvalue.Object:
			if withText == nil {
				withText = slices.Clone(tokens)
			}
			withText = append(withText, "t:"+legacyvalue.Fold(structureText(e)))
		}
	}
	if withText == nil {
		withText = tokens
	}
	return tokens, withText
}

// eqToken returns the token two elements are equal by when neither is a
// string facing a list or an object: a scalar by its key, as
// equalsIgnoreCase compares the texts; an object by its members, with their
// case; a list by its elements in order, each by its token. Null equals
// nothing, so null and a list that holds one have no token.
func eqToken(e jsonvalue.Value) (string, bool) {
	switch e := e.(type) {
	case nil:
		return "", false
	case *jsonvalue.Object:
		return "o:" + *legacyvalue.Of(e).Structure, true
	case []jsonvalue.Value:
		return listToken(e, eqToken)
	}
	return "t:" + *legacyvalue.Of(e).Key, true
}

// listToken returns the token of a list by the tokens of its elements in
// order: leaf gives the token of an element other than a list, and the list
// has no token where leaf gives none for an element at any depth. Each leaf
// token is quoted once and each level of nesting adds "l:[" and "]", so the
// length of the token is linear in the size of the list.
func listToken(l []jsonvalue.Value, leaf func(jsonvalue.Value) (string, bool)) (string, bool) {
	var b strings.Builder
	if !writeListToken(&b, l, leaf) {
		return "", false
	}
	return b.String(), true
}

func writeListToken(b *strings.Builder, l []jsonvalue.Value, leaf func(jsonvalue.Value) (string, bool)) bool {
	b.WriteString("l:[")
	for i, e := range l {
		if i > 0 {
			b.WriteByte(',')
		}
		if nested, ok := e.([]jsonvalue.Value); ok {
			if !writeListToken(b, nested, leaf) {
				return false
			}
			continue
		}
		t, ok := leaf(e)
		if !ok {
			return false
		}
		b.WriteString(strconv.Quote(t))
	}
	b.WriteByte(']')
	return true
}

// Project builds the input of the module for a request. It fails when the
// request lacks the resolved value of an operand the module reads, or the
// permission scope of a module that iterates. A GENERAL or FILTERED PIP
// needs no value, since the module calls it.
func Project(m *Module, req Request) (*Input, error) {
	in := &Input{Records: map[string]Record{}, M2M: req.M2M, refs: m.Refs, docs: regobuiltins.NewDocuments()}
	if req.Body.HasResource {
		in.resource = req.Body.Resource
	}
	for _, r := range req.Roles {
		in.FoldedRoles = append(in.FoldedRoles, legacyvalue.Fold(r))
	}
	for _, r := range m.Refs {
		if r.Pass || r.Path != "" {
			continue
		}
		var v Resolved
		switch r.Kind {
		case spectables.KindOperation:
			v = Resolved{State: spectables.StateValue, Value: req.Body.Operation}
		case spectables.KindResourceType:
			v = Resolved{State: spectables.StateValue, Value: req.Body.ResourceType}
		default:
			var ok bool
			if v, ok = req.Values[r.Key]; !ok {
				if r.pip != nil || r.ent != nil {
					// the module calls the PIP itself
					continue
				}
				return nil, fmt.Errorf("no resolved value of %s (%s)", r.Key, r.ID)
			}
		}
		in.Records[r.ID] = record(r, v)
	}
	if m.Iterates {
		if req.Scope == nil {
			return nil, fmt.Errorf("no permission scope for the iterate of the module")
		}
		in.ScopeFailed = req.Scope.Failed
		for i, values := range req.Scope.Passes {
			pass := map[string]Record{}
			for _, r := range m.Refs {
				if !r.Pass {
					continue
				}
				v, ok := values[r.Key]
				if !ok {
					return nil, fmt.Errorf("no resolved value of %s (%s) in pass %d", r.Key, r.ID, i)
				}
				pass[r.ID] = record(r, v)
			}
			in.Passes = append(in.Passes, pass)
		}
	}
	if err := in.setCalls(m, &req); err != nil {
		return nil, err
	}
	in.SubjectGroups = EvalGroups(m, in)
	return in, nil
}

// setCalls sets in the q of each GENERAL or FILTERED PIP of m on req
// ([pipCall]). It fails where req lacks the value of a subject's operand a
// request of such a PIP reads ([Module.Placeholders]).
func (in *Input) setCalls(m *Module, req *Request) error {
	for _, k := range m.placeholders {
		if _, ok := req.Values[k]; !ok {
			return fmt.Errorf("no resolved value of %s, which the request of a PIP reads", k)
		}
	}
	for _, r := range m.Refs {
		if r.pip == nil && r.ent == nil {
			continue
		}
		if in.calls == nil {
			in.calls = ast.NewObject()
			in.pipValues = map[string]Resolved{}
		}
		if r.ent != nil {
			in.calls.Insert(strTerm(r.ID), entCall(req))
			continue
		}
		in.calls.Insert(strTerm(r.ID), pipCall(r, req, m.pips))
		if v, ok := req.Values[r.Key]; ok {
			in.pipValues[r.ID] = v
		}
	}
	return nil
}

// Placeholders returns the keys of the subject's operands that the request
// of a GENERAL or FILTERED PIP of m reads from [Request.Values], besides the
// operands m reads itself.
func (m *Module) Placeholders() []string { return m.placeholders }

func strTerm(s string) *ast.Term { return ast.StringTerm(s) }

func strsTerm(ss []string) *ast.Term {
	ts := make([]*ast.Term, len(ss))
	for i, s := range ss {
		ts[i] = ast.StringTerm(s)
	}
	return ast.ArrayTerm(ts...)
}

// keysTerm is the term of a list the module only tests membership in or
// iterates, element_keys, element_tokens, element_tokens_with_text, or
// subset_right: a Rego set, so that x in it costs one lookup
// and not a scan of the list.
func keysTerm(ss []string) *ast.Term {
	ts := make([]*ast.Term, len(ss))
	for i, s := range ss {
		ts[i] = ast.StringTerm(s)
	}
	return ast.SetTerm(ts...)
}

func setsTerm(sets [][]string) *ast.Term {
	ts := make([]*ast.Term, len(sets))
	for i, s := range sets {
		ts[i] = strsTerm(s)
	}
	return ast.ArrayTerm(ts...)
}

func (r Record) term() *ast.Term {
	o := ast.NewObject([2]*ast.Term{strTerm(fieldState), strTerm(r.State)})
	if r.Class != "" {
		o.Insert(strTerm(fieldClass), strTerm(r.Class))
	}
	if r.Key != nil {
		o.Insert(strTerm(fieldKey), strTerm(*r.Key))
	}
	if r.ElementKeys != nil {
		o.Insert(strTerm(fieldElementKeys), keysTerm(r.ElementKeys))
	}
	if r.Text != nil {
		o.Insert(strTerm(fieldText), strTerm(*r.Text))
	}
	if r.HasNull {
		o.Insert(strTerm(fieldHasNull), ast.BooleanTerm(true))
	}
	if r.TextKey != nil {
		o.Insert(strTerm(fieldTextKey), strTerm(*r.TextKey))
	}
	if r.EqualityKey != nil {
		o.Insert(strTerm(fieldEqualityKey), strTerm(*r.EqualityKey))
	}
	if r.Length != nil {
		o.Insert(strTerm(fieldLength), ast.IntNumberTerm(*r.Length))
	}
	if r.ElementTokens != nil {
		tokens := keysTerm(r.ElementTokens)
		o.Insert(strTerm(fieldElementTokens), tokens)
		o.Insert(strTerm(fieldElementTokensWithText), r.withTextTerm(tokens))
	}
	if r.Number != nil {
		o.Insert(strTerm(fieldNumber), orderKey(*r.Number))
	}
	if r.SubsetLeft != nil {
		o.Insert(strTerm(fieldSubsetLeft), setsTerm(r.SubsetLeft))
		o.Insert(strTerm(fieldSubsetRight), keysTerm(r.SubsetRight))
	}
	return ast.NewTerm(o)
}

// Value returns the input as a Rego value: the maps [recordFields] from a
// reference ID to a field of its record, then folded_roles, m2m,
// subject_groups, scope_passes (the passes, each with the same maps of its
// pass values), scope_failed, for a module with a lazily read resource path
// resource, the document, and for a module with a GENERAL or FILTERED PIP
// pip_requests, the requests of its calls. A network PIP's record is not in
// it: its function pip_<Var>, or nc.pip, returns it.
func (in *Input) Value() ast.Value {
	if in.bulk != nil {
		return in.bulk.value(in)
	}
	o := fieldMaps(in.refs, func(r *Ref) (Record, bool) {
		rec, ok := in.Records[r.ID]
		return rec, ok && !r.Network && !r.Pass
	})
	for _, kv := range in.subjectMembers() {
		o.Insert(kv[0], kv[1])
	}
	if in.resourceMember() {
		res := ast.NullTerm()
		if in.resource != nil {
			// a jsonvalue.Value always has a term
			res, _ = in.docs.Term(in.resource)
		}
		o.Insert(strTerm(memberResource), res)
	}
	if in.calls != nil {
		o.Insert(strTerm(memberPIPRequests), ast.NewTerm(in.calls))
	}
	return o
}

// resourceMember reports whether the input carries the member resource: the
// module reads a resource path lazily.
func (in *Input) resourceMember() bool {
	return slices.ContainsFunc(in.refs, func(r *Ref) bool { return r.Path != "" })
}

// subjectMembers returns the members folded_roles, m2m, subject_groups,
// scope_passes, and scope_failed of the input's Value.
func (in *Input) subjectMembers() [][2]*ast.Term {
	passes := make([]*ast.Term, len(in.Passes))
	for i, pass := range in.Passes {
		passes[i] = ast.NewTerm(fieldMaps(in.refs, func(r *Ref) (Record, bool) {
			rec, ok := pass[r.ID]
			return rec, ok
		}))
	}
	return [][2]*ast.Term{
		{strTerm(memberFoldedRoles), strsTerm(in.FoldedRoles)},
		{strTerm(memberM2M), ast.BooleanTerm(in.M2M)},
		{strTerm(memberSubjectGroups), strsTerm(in.SubjectGroups)},
		{strTerm(memberScopePasses), ast.ArrayTerm(passes...)},
		{strTerm(memberScopeFailed), ast.BooleanTerm(in.ScopeFailed)},
	}
}

// fieldMaps returns the object of the maps from a reference ID to a field of
// its record, for each reference whose record rec gives.
func fieldMaps(refs []*Ref, rec func(*Ref) (Record, bool)) ast.Object {
	o := ast.NewObject()
	for f, v := range fieldObjects(refs, rec) {
		o.Insert(strTerm(f), ast.NewTerm(v))
	}
	return o
}

// The names of the fields of a value record, each also the name of the map of
// [fieldMaps] from a reference ID to that field of its record. A module reads
// them as input.<field>, p.<field> in a pass, or p_<Var>.<field>.
const (
	fieldState                 = "state"
	fieldClass                 = "class"
	fieldKey                   = "key"
	fieldElementKeys           = "element_keys"
	fieldText                  = "text"
	fieldSegments              = "segments"
	fieldSegmentsFromEnd       = "segments_from_end"
	fieldSegmentCount          = "segment_count"
	fieldHasNull               = "has_null"
	fieldTextKey               = "text_key"
	fieldEqualityKey           = "equality_key"
	fieldLength                = "length"
	fieldElementTokens         = "element_tokens"
	fieldElementTokensWithText = "element_tokens_with_text"
	fieldNumber                = "number"
	fieldSubsetLeft            = "subset_left"
	fieldSubsetRight           = "subset_right"
)

// The names of the members of the input besides the maps of [fieldMaps].
const (
	memberFoldedRoles   = "folded_roles"
	memberM2M           = "m2m"
	memberSubjectGroups = "subject_groups"
	memberScopePasses   = "scope_passes"
	memberScopeFailed   = "scope_failed"
	memberResource      = "resource"
	memberPIPRequests   = "pip_requests"
)

// recordFields names the maps of [fieldMaps].
var recordFields = []string{fieldState, fieldClass, fieldKey, fieldElementKeys, fieldText, fieldSegments,
	fieldSegmentsFromEnd, fieldSegmentCount, fieldHasNull, fieldTextKey, fieldEqualityKey, fieldLength,
	fieldElementTokens, fieldElementTokensWithText, fieldNumber, fieldSubsetLeft, fieldSubsetRight}

// fieldSet holds names of recordFields, one bit each, and fieldsKnown.
type fieldSet uint32

// fieldsKnown marks the fieldSet of a reference the generator created.
const fieldsKnown fieldSet = 1 << 31

func fieldBit(f string) fieldSet {
	i := slices.Index(recordFields, f)
	if i < 0 {
		panic("regogen: no record field " + f)
	}
	return 1 << i
}

// has reports whether fs holds one of the fields f, and is true for the
// fieldSet of a reference the generator did not create.
func (fs fieldSet) has(f ...string) bool {
	if fs&fieldsKnown == 0 {
		return true
	}
	for _, x := range f {
		if fs&fieldBit(x) != 0 {
			return true
		}
	}
	return false
}

// reads reports whether the module reads one of the fields fs of r's record,
// and is true for a reference the generator did not create.
func (r *Ref) reads(fs ...string) bool { return r.read.has(fs...) }

// fieldReadRE matches a read of a record field in the text of a module:
// input.<field> or p.<field>, the record of a pass value, then the index of
// the reference where the text names one.
var fieldReadRE = regexp.MustCompile(`\b(?:input|p)\.([a-z][a-z0-9_]*)(\.[A-Za-z_][A-Za-z0-9_]*|\["(?:[^"\\]|\\.)*"\])?`)

// markEmitted sets the emit of each reference to the fields that texts read
// of its record. A field read with no index, of whichever reference, is set
// for every reference.
func markEmitted(refs []*Ref, texts ...string) {
	byIndex := make(map[string]*Ref, len(refs))
	for _, r := range refs {
		r.emit = fieldsKnown
		byIndex[refIndex(r.ID)] = r
	}
	for _, text := range texts {
		for _, m := range fieldReadRE.FindAllStringSubmatch(text, -1) {
			i := slices.Index(recordFields, m[1])
			if i < 0 {
				continue
			}
			if m[2] == "" {
				for _, r := range refs {
					r.emit |= 1 << i
				}
			} else if r, ok := byIndex[m[2]]; ok {
				r.emit |= 1 << i
			}
		}
	}
}

// parts are the parts of the legacyvalue record of a list that the fields
// the module reads of r come from.
func (r *Ref) parts() legacyvalue.Parts {
	if r.read&fieldsKnown == 0 {
		return legacyvalue.AllParts
	}
	var p legacyvalue.Parts
	if r.reads(fieldTextKey) {
		p |= legacyvalue.PartKey
	}
	if r.reads(fieldElementKeys) {
		p |= legacyvalue.PartKeys
	}
	if r.reads(fieldEqualityKey) {
		p |= legacyvalue.PartStructure
	}
	if r.reads(fieldElementTokens, fieldElementTokensWithText) {
		p |= legacyvalue.PartElements
	}
	return p
}

// fieldObjects returns the maps of [fieldMaps] by their names.
func fieldObjects(refs []*Ref, rec func(*Ref) (Record, bool)) map[string]ast.Object {
	fields := make(map[string]ast.Object, len(recordFields))
	for _, f := range recordFields {
		fields[f] = ast.NewObject()
	}
	for _, r := range refs {
		if rec, ok := rec(r); ok {
			id := strTerm(r.ID)
			rec.fields(r.emit, func(f string, v *ast.Term) { fields[f].Insert(id, v) })
		}
	}
	return fields
}

// withTextTerm returns the term of ElementTokensWithText, which is tokens,
// the term of ElementTokens, where the two are one slice (elementTokens).
func (rec Record) withTextTerm(tokens *ast.Term) *ast.Term {
	toks, withText := rec.ElementTokens, rec.ElementTokensWithText
	if len(withText) == len(toks) && (len(toks) == 0 || &withText[0] == &toks[0]) {
		return tokens
	}
	return keysTerm(rec.ElementTokensWithText)
}

// fields gives put each entry of the record in the maps of [fieldMaps] that
// emit holds: the name of the map and the value under the reference's ID.
func (rec Record) fields(emit fieldSet, put func(field string, v *ast.Term)) {
	if emit.has(fieldState) {
		put(fieldState, strTerm(rec.State))
	}
	if rec.Class != "" && emit.has(fieldClass) {
		put(fieldClass, strTerm(rec.Class))
	}
	if rec.Key != nil && emit.has(fieldKey) {
		put(fieldKey, strTerm(*rec.Key))
	}
	if rec.ElementKeys != nil && emit.has(fieldElementKeys) {
		put(fieldElementKeys, keysTerm(rec.ElementKeys))
	}
	if rec.Text != nil && emit.has(fieldText) {
		put(fieldText, strTerm(*rec.Text))
	}
	if rec.HasNull && emit.has(fieldHasNull) {
		put(fieldHasNull, ast.BooleanTerm(true))
	}
	if rec.TextKey != nil && emit.has(fieldTextKey) {
		put(fieldTextKey, strTerm(*rec.TextKey))
	}
	if rec.EqualityKey != nil && emit.has(fieldEqualityKey) {
		put(fieldEqualityKey, strTerm(*rec.EqualityKey))
	}
	if rec.Length != nil && emit.has(fieldLength) {
		put(fieldLength, ast.IntNumberTerm(*rec.Length))
	}
	if rec.ElementTokens != nil && emit.has(fieldElementTokens, fieldElementTokensWithText) {
		tokens := keysTerm(rec.ElementTokens)
		if emit.has(fieldElementTokens) {
			put(fieldElementTokens, tokens)
		}
		if emit.has(fieldElementTokensWithText) {
			put(fieldElementTokensWithText, rec.withTextTerm(tokens))
		}
	}
	if rec.Number != nil && emit.has(fieldNumber) {
		put(fieldNumber, orderKey(*rec.Number))
	}
	if rec.SubsetLeft != nil {
		if emit.has(fieldSubsetLeft) {
			put(fieldSubsetLeft, setsTerm(rec.SubsetLeft))
		}
		if emit.has(fieldSubsetRight) {
			put(fieldSubsetRight, keysTerm(rec.SubsetRight))
		}
	}
	if rec.Segments != nil {
		if emit.has(fieldSegments) {
			put(fieldSegments, strsTerm(rec.Segments))
		}
		if emit.has(fieldSegmentsFromEnd) {
			rev := slices.Clone(rec.Segments)
			slices.Reverse(rev)
			put(fieldSegmentsFromEnd, strsTerm(rev))
		}
		if emit.has(fieldSegmentCount) {
			put(fieldSegmentCount, ast.IntNumberTerm(len(rec.Segments)))
		}
	}
}

// PIPRecord returns the record nc.pip returns for a network reference, and
// false for an unknown one.
func (in *Input) PIPRecord(id string) (*ast.Term, bool) {
	r, ok := in.Records[id]
	if !ok && in.bulk != nil {
		r, ok = in.bulk.in.Records[id]
	}
	if !ok {
		return nil, false
	}
	return r.term(), true
}

func allStrings(l []jsonvalue.Value) bool {
	for _, e := range l {
		if _, ok := e.(string); !ok {
			return false
		}
	}
	return true
}

// structureText is the text a string compares a list or an object by, as the
// agent profile prints it: the members in document order, a scalar member as
// its Java text with a number as structureNumberText prints it, and a member
// that is itself a list or an object as compact JSON with its numbers as
// written.
func structureText(v jsonvalue.Value) string {
	member := func(x jsonvalue.Value) string {
		switch x := x.(type) {
		case []jsonvalue.Value, *jsonvalue.Object:
			return jsonText(x)
		case nil:
			return "null"
		case bool:
			return strconv.FormatBool(x)
		case jsonvalue.Number:
			return structureNumberText(string(x))
		case string:
			return x
		}
		return ""
	}
	var parts []string
	switch v := v.(type) {
	case []jsonvalue.Value:
		for _, x := range v {
			parts = append(parts, member(x))
		}
		return "[" + strings.Join(parts, ", ") + "]"
	case *jsonvalue.Object:
		for _, k := range v.Keys() {
			x, _ := v.Get(k)
			parts = append(parts, k+"="+member(x))
		}
		return "{" + strings.Join(parts, ", ") + "}"
	}
	return member(v)
}

// jsonText is compact JSON with the numbers as the document writes them.
func jsonText(v jsonvalue.Value) string {
	var b strings.Builder
	writeJSONText(&b, v)
	return b.String()
}

func writeJSONText(b *strings.Builder, v jsonvalue.Value) {
	switch v := v.(type) {
	case []jsonvalue.Value:
		b.WriteByte('[')
		for i, x := range v {
			if i > 0 {
				b.WriteByte(',')
			}
			writeJSONText(b, x)
		}
		b.WriteByte(']')
	case *jsonvalue.Object:
		b.WriteByte('{')
		for i, k := range v.Keys() {
			if i > 0 {
				b.WriteByte(',')
			}
			x, _ := v.Get(k)
			b.WriteString(jsonString(k))
			b.WriteByte(':')
			writeJSONText(b, x)
		}
		b.WriteByte('}')
	case jsonvalue.Number:
		b.WriteString(string(v))
	case string:
		b.WriteString(jsonString(v))
	case bool:
		b.WriteString(strconv.FormatBool(v))
	default:
		b.WriteString("null")
	}
}

func jsonString(s string) string {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(s)
	return strings.TrimSuffix(b.String(), "\n")
}

var numberRE = regexp.MustCompile(`^(-?)(\d*)(?:\.(\d*))?(?:[eE]([-+]?\d+))?$`)

// structureNumberText is the text of a number that is a member of a list or
// an object in structureText: Double.toString of a number with an exponent
// and no digits after the point that the exponent leaves, such as 1e3, 1.5e1,
// or 5e0, which print 1000.0, 15.0, and 5.0; plainStripped of any other.
func structureNumberText(text string) string {
	m := numberRE.FindStringSubmatch(text)
	if m == nil || m[4] == "" || strings.HasPrefix(m[4], "-") {
		return plainStripped(text)
	}
	// an exponent too long for an int64 leaves no digits after the point
	if exp, err := strconv.ParseInt(m[4], 10, 64); err == nil && int64(len(m[3])) > exp {
		return plainStripped(text)
	}
	// a number beyond the range of a float64 parses as an infinity with
	// ErrRange, and DoubleText prints it as Infinity
	f, _ := strconv.ParseFloat(text, 64)
	return jsonvalue.DoubleText(f)
}

// plainZeroLimit is the most zeros plainStripped adds to the digits of a
// number to write it in plain notation: 1e999999999 would take a gigabyte.
const plainZeroLimit = 64

// plainStripped is BigDecimal.stripTrailingZeros().toPlainString() of a
// number's text: 5.50 is 5.5, 5.0 is 5, 1e3 is 1000. A number that needs
// more than plainZeroLimit zeros, such as 1e65 or 1e-66, keeps its text as
// written, where legacy prints every zero.
func plainStripped(text string) string {
	m := numberRE.FindStringSubmatch(text)
	if m == nil {
		return text
	}
	coef := strings.TrimLeft(m[2]+m[3], "0")
	exp := -len(m[3])
	if m[4] != "" {
		e, err := strconv.Atoi(m[4])
		if err != nil {
			return text
		}
		exp += e
	}
	for strings.HasSuffix(coef, "0") {
		coef = coef[:len(coef)-1]
		exp++
	}
	if coef == "" {
		return "0"
	}
	if exp > plainZeroLimit || -(len(coef)+exp) > plainZeroLimit {
		return text
	}
	var out string
	switch point := len(coef) + exp; {
	case exp >= 0:
		out = coef + strings.Repeat("0", exp)
	case point > 0:
		out = coef[:point] + "." + coef[point:]
	default:
		out = "0." + strings.Repeat("0", -point) + coef
	}
	return m[1] + out
}
