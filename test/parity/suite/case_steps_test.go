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

package paritysuite

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"maps"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"

	"authz-agent/test/parity/suite/model"
)

// papOperationsJSON is the operation table testdata/pap-operations.json, which
// the spec repository generates from its own vocabulary (pap_ops.py export).
//
//go:embed testdata/pap-operations.json
var papOperationsJSON []byte

// papOperation is one PAP operation a step names: a write, a delete, or a
// read, and the endpoints that perform it, by binding name.
type papOperation struct {
	Kind     string                `json:"kind"`
	Bindings map[string]papBinding `json:"bindings"`
}

// papBinding is one endpoint of an operation. Path holds {name} for each path
// parameter; Query names the query parameters it takes; Args, when it lists a
// parameter, holds the values that parameter may take. Golden is the golden
// kind a write's status is recorded under. Tier is contract, primary, or
// variant.
type papBinding struct {
	Method string              `json:"method"`
	Path   string              `json:"path"`
	Query  []string            `json:"query"`
	Tier   string              `json:"tier"`
	Golden string              `json:"golden"`
	Args   map[string][]string `json:"args"`
}

var (
	papOperationsOnce sync.Once
	papOperationsByOp map[string]papOperation
)

// papOperations returns the operation table by operation name.
func papOperations() map[string]papOperation {
	papOperationsOnce.Do(func() {
		var table struct {
			Ops map[string]papOperation `json:"ops"`
		}
		if err := json.Unmarshal(papOperationsJSON, &table); err != nil {
			panic(fmt.Sprintf("testdata/pap-operations.json: %v", err)) // embedded, so a bad file fails every test
		}
		papOperationsByOp = table.Ops
	})
	return papOperationsByOp
}

var pathParam = regexp.MustCompile(`\{(\w+)\}`)

// bindingOf returns the binding called name of op, or, when name is empty, its
// primary binding, else its contract binding.
func bindingOf(op papOperation, name string) (papBinding, string, bool) {
	if name != "" {
		b, ok := op.Bindings[name]
		return b, name, ok
	}
	for _, tier := range []string{"primary", "contract"} {
		for _, n := range slices.Sorted(maps.Keys(op.Bindings)) {
			if op.Bindings[n].Tier == tier {
				return op.Bindings[n], n, true
			}
		}
	}
	return papBinding{}, "", false
}

// stepSpec is one step of a case: a call to the PAP operation Op through the
// binding Binding, its primary one when empty, followed by the observations
// Observe names, in order:
//
//   - status: the status of the call, under the binding's golden kind;
//   - error-class: the status and the error body of the call, under pap-error-v1;
//   - read:<op>: a GET through the read operation op with the step's Args,
//     under pap-read;
//   - decide:<name>: the request called name of Requests, recorded as a
//     case's requests are;
//   - pip-call:<route>: what route received from the call to the observation,
//     under pip-call.
//
// A step whose operation is a read sends no call of its own, takes no
// Binding, and observes read:<its op> when Observe is empty; a write or delete
// step observes status when Observe is empty, and its Observe starts with
// status, followed by error-class when it has one. When the PAP refuses the
// call, OnRefusal stop, the default, records status and error-class and ends
// the case; continue goes on with the step's other observations and the steps
// after it. Golden paths are <kind>/<group>/<case>/<step>, where the group is
// regular or sequence, so a step's name differs from every request name of
// its case and, in a case with sets, from upload-1 and declare-the-domain.
type stepSpec struct {
	Name    string `json:"name"`
	Op      string `json:"op"`
	Binding string `json:"binding"`
	// Args holds the path and query parameters of the binding, strings or
	// booleans; strings take the resource type placeholders.
	Args map[string]any `json:"args"`
	// Body, when present, is the body of the call, sent with the resource type
	// placeholders replaced; JSON null is sent as null.
	Body      json.RawMessage `json:"body"`
	Observe   []string        `json:"observe"`
	OnRefusal string          `json:"onRefusal"`
	Requests  []requestSpec   `json:"requests"`
	// Markers narrows the body of a read observation: an array keeps the
	// elements whose JSON text contains one of them. The step's case id, its
	// resource type, and its string Args are markers too.
	Markers []string `json:"markers"`
}

// observation is one entry of stepSpec.Observe: its kind and its argument.
type observation struct{ kind, arg string }

func parseObservation(text string) observation {
	kind, arg, _ := strings.Cut(text, ":")
	return observation{kind, arg}
}

// stepObserve returns the observations of st, its Observe or the default of
// its operation's kind.
func stepObserve(st stepSpec, op papOperation) []string {
	switch {
	case len(st.Observe) > 0:
		return st.Observe
	case op.Kind == "read":
		return []string{"read:" + st.Op}
	}
	return []string{"status"}
}

// argText returns the text of a step argument as the call sends it, with the
// resource type placeholders of rt replaced.
func argText(v any, rt string) string {
	switch x := v.(type) {
	case string:
		return resourceTypeReplacer(rt).Replace(x)
	case bool:
		return strconv.FormatBool(x)
	}
	return fmt.Sprint(v)
}

// bindingCall returns the call b makes with args: each {param} of its path
// replaced by the argument, escaped as one path segment, and each query
// parameter the args give.
func bindingCall(b papBinding, args map[string]any, rt string) (papCall, error) {
	var missing []string
	path := pathParam.ReplaceAllStringFunc(b.Path, func(m string) string {
		name := m[1 : len(m)-1]
		v, ok := args[name]
		if !ok {
			missing = append(missing, name)
			return m
		}
		return url.PathEscape(argText(v, rt))
	})
	if len(missing) > 0 {
		return papCall{}, fmt.Errorf("no argument for the path parameter %s", strings.Join(missing, ", "))
	}
	query := url.Values{}
	for _, name := range b.Query {
		if v, ok := args[name]; ok {
			query.Set(name, argText(v, rt))
		}
	}
	return papCall{method: b.Method, path: path, query: query}, nil
}

// goldenEndpoint returns the endpoint whose golden directory is dir.
func goldenEndpoint(dir string) (ParityEndpointID, bool) {
	for id, m := range rowMetas {
		if m.GoldenDir == dir {
			return id, true
		}
	}
	return 0, false
}

// stepCall returns the call st makes for a case whose resource type is rt, and
// the endpoint its status is recorded under; a read step returns no call.
func stepCall(st stepSpec, rt string) (*papCall, ParityEndpointID, error) {
	op, ok := papOperations()[st.Op]
	if !ok {
		return nil, 0, fmt.Errorf("names the operation %q, which testdata/pap-operations.json does not hold", st.Op)
	}
	b, name, ok := bindingOf(op, st.Binding)
	if !ok {
		return nil, 0, fmt.Errorf("names the binding %q, which the operation %s does not have", st.Binding, st.Op)
	}
	if op.Kind == "read" {
		return nil, 0, nil
	}
	if strings.Contains(b.Path, "*") {
		return nil, 0, fmt.Errorf("calls %s/%s, whose path %s names no single endpoint", st.Op, name, b.Path)
	}
	call, err := bindingCall(b, st.Args, rt)
	if err != nil {
		return nil, 0, err
	}
	if st.Body != nil {
		call.body = withResourceType(decodeRaw(st.Body), rt)
		if call.body == nil {
			call.body = json.RawMessage("null") // a nil body would send no body at all
		}
	}
	golden, ok := goldenEndpoint(b.Golden)
	if !ok {
		return nil, 0, fmt.Errorf("records its status under %q, which no endpoint of the catalog files goldens under", b.Golden)
	}
	return &call, golden, nil
}

// readCall returns the GET the observation read:<op> sends with the step's
// args.
func readCall(op string, args map[string]any, rt string) (papCall, error) {
	o, ok := papOperations()[op]
	if !ok || o.Kind != "read" {
		return papCall{}, fmt.Errorf("reads through %q, which is no read operation of testdata/pap-operations.json", op)
	}
	b, name, _ := bindingOf(o, "")
	if b.Method != "GET" || strings.Contains(b.Path, "*") {
		return papCall{}, fmt.Errorf("reads through %s/%s, which is no GET of a single endpoint", op, name)
	}
	return bindingCall(b, args, rt)
}

// stepMarkers returns the markers a read observation of st narrows its body
// by: Markers, the case id, the resource type, and every string argument.
func stepMarkers(caseID, rt string, st stepSpec) []string {
	markers := append([]string{caseID, rt}, st.Markers...)
	for _, name := range slices.Sorted(maps.Keys(st.Args)) {
		if s, ok := st.Args[name].(string); ok {
			markers = append(markers, resourceTypeReplacer(rt).Replace(s))
		}
	}
	return markers
}

// narrowStepRead turns the answer to a step's read into its golden shape:
// narrowPAPRead of the body, with hash and lastModificationTimestamp removed
// from an object body first, and the distinct tenantId values of the whole
// 2xx body, sorted.
func narrowStepRead(status int, body []byte, markers []string) *model.PapReadOutcome {
	var decoded any
	if status >= 200 && status <= 299 && json.Unmarshal(body, &decoded) == nil {
		tenants := map[string]bool{}
		collectTenants(decoded, tenants)
		if envelope, ok := decoded.(map[string]any); ok {
			for _, field := range configExportEnvelopeFields {
				delete(envelope, field)
			}
			body, _ = json.Marshal(envelope)
		}
		outcome := narrowPAPRead(status, body, markers)
		for tenant := range tenants {
			outcome.Tenants = append(outcome.Tenants, tenant)
		}
		sort.Strings(outcome.Tenants)
		return outcome
	}
	return narrowPAPRead(status, body, markers)
}

func collectTenants(v any, into map[string]bool) {
	switch x := v.(type) {
	case map[string]any:
		for key, value := range x {
			if s, ok := value.(string); ok && key == "tenantId" {
				into[s] = true
			}
			collectTenants(value, into)
		}
	case []any:
		for _, e := range x {
			collectTenants(e, into)
		}
	}
}

// errorOutcome returns the golden shape of an error-class observation: the
// status, and for a non-2xx answer its body, decoded when it is JSON, with
// every top-level timestamp member removed, since it changes on every call.
// A text body, and every top-level string member of a JSON one, lose the
// reference chain tail, since it names the server's own classes.
func errorOutcome(status int, body []byte) *model.PapErrorOutcome {
	out := &model.PapErrorOutcome{Status: status}
	if status >= 200 && status <= 299 {
		return out
	}
	var decoded any
	if err := json.Unmarshal(body, &decoded); err != nil {
		out.Body = withoutReferenceChain(string(body))
		return out
	}
	if object, ok := decoded.(map[string]any); ok {
		delete(object, "timestamp")
		for key, value := range object {
			if text, ok := value.(string); ok {
				object[key] = withoutReferenceChain(text)
			}
		}
	}
	out.Body = decoded
	return out
}

// referenceChain opens the tail the server adds to the message about a body
// it cannot read: " (through reference chain: <its classes and fields>)".
const referenceChain = " (through reference chain: "

// withoutReferenceChain returns message cut where its reference chain tail
// starts, or message as it is when it has none.
func withoutReferenceChain(message string) string {
	if i := strings.Index(message, referenceChain); i >= 0 {
		return message[:i]
	}
	return message
}

// caseStepProblems returns the problems of st, a step of the case c, by
// itself; caseFileProblems checks it against the rest of the case.
func caseStepProblems(c caseSpec, st stepSpec) []string {
	var problems []string
	report := func(format string, args ...any) {
		problems = append(problems, fmt.Sprintf("case %s step %s ", c.ID, st.Name)+fmt.Sprintf(format, args...))
	}
	op, known := papOperations()[st.Op]
	if !known {
		report("names the operation %q, which testdata/pap-operations.json does not hold", st.Op)
		return problems
	}
	b, bname, ok := bindingOf(op, st.Binding)
	if !ok {
		report("names the binding %q, which the operation %s does not have", st.Binding, st.Op)
		return problems
	}
	if strings.HasPrefix(st.Op, "decide") {
		report("names the decision %s, which a request of decide: observes", st.Op)
		return problems
	}
	if _, _, err := stepCall(st, "RT"); err != nil {
		report("%v", err)
	}
	params := pathParam.FindAllStringSubmatch(b.Path, -1)
	takes := slices.Clone(b.Query)
	for _, p := range params {
		takes = append(takes, p[1])
	}
	for _, name := range slices.Sorted(maps.Keys(st.Args)) {
		v := st.Args[name]
		if !slices.Contains(takes, name) {
			report("sets the argument %s, which %s/%s does not take", name, st.Op, bname)
			continue
		}
		switch v.(type) {
		case string, bool:
		default:
			report("sets the argument %s to %v, which is neither a string nor a boolean", name, v)
		}
		if allowed := b.Args[name]; len(allowed) > 0 && !slices.Contains(allowed, argText(v, "RT")) {
			report("sets the argument %s to %v, which is none of %s", name, v, strings.Join(allowed, ", "))
		}
	}
	read := op.Kind == "read"
	if read && (st.Body != nil || st.OnRefusal != "" || st.Binding != "") {
		report("sets body, onRefusal, or binding on the read %s, which sends no call of its own", st.Op)
	}
	if st.OnRefusal != "" && st.OnRefusal != "stop" && st.OnRefusal != "continue" {
		report("sets onRefusal %q, which is neither stop nor continue", st.OnRefusal)
	}
	observe := stepObserve(st, op)
	if !read && observe[0] != "status" {
		report("observes %s first, where a write starts with status", observe[0])
	}
	for i, text := range observe {
		o := parseObservation(text)
		if (o.kind == "status" || o.kind == "error-class") && (text != o.kind || (o.kind == "error-class" && i != 1)) {
			report("observes %q at %d, where error-class comes right after status and neither takes an argument", text, i+1)
		}
	}
	seen := map[string]bool{}
	decided := map[string]bool{}
	for _, text := range observe {
		o := parseObservation(text)
		golden := o.kind
		switch o.kind {
		case "status", "error-class":
			if read {
				report("observes %s on the read %s, which sends no call of its own", o.kind, st.Op)
			}
		case "read":
			golden = "read"
			if _, err := readCall(o.arg, st.Args, "RT"); err != nil {
				report("%v", err)
			}
		case "decide":
			golden = "decide:" + o.arg
			if !slices.ContainsFunc(st.Requests, func(r requestSpec) bool { return r.Name == o.arg }) {
				report("observes decide:%s, and no request of the step has that name", o.arg)
			}
			decided[o.arg] = true
		case "pip-call":
			golden = "pip-call"
			if o.arg == "" {
				report("observes pip-call with no route")
			}
		default:
			report("observes %q, which is none of status, error-class, read:<op>, decide:<request>, pip-call:<route>", text)
		}
		if seen[golden] {
			report("observes %s twice, and both would record the same golden", golden)
		}
		seen[golden] = true
	}
	for _, r := range st.Requests {
		if !decided[r.Name] {
			report("has the request %s, which no decide: observation sends", r.Name)
		}
	}
	return problems
}

// stepRoutes returns the routes of the pip-call observations of st.
func stepRoutes(st stepSpec) []string {
	var out []string
	for _, text := range st.Observe {
		if o := parseObservation(text); o.kind == "pip-call" {
			out = append(out, o.arg)
		}
	}
	return out
}

// sequenceProblems returns the problems of c, a case with steps and no sets,
// and of its tenant: such a case reads its steps and pins only.
func sequenceProblems(c caseSpec) []string {
	var problems []string
	if c.Condition != "" || c.Operation != "" || c.PIPs != nil || c.Requests != nil || c.Roles != nil ||
		c.Domain != "" || c.PolicyOmit != nil || c.Policy != nil || c.PoliciesQuery != "" || c.Customize != nil ||
		c.ReadsRoutes != nil || c.PIPCalls != "" || c.RuleIDsOf != "" {
		problems = append(problems, fmt.Sprintf("case %s has steps and no sets, and sets a field other than "+
			"id, about, resourceType, tenant, pins, and steps, which such a case does not read", c.ID))
	}
	if len(c.Steps) == 0 {
		problems = append(problems, fmt.Sprintf("case %s sets steps to an empty list", c.ID))
	}
	return problems
}
