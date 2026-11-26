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
	"bufio"
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"

	"authz-agent/internal/policyir"
	"authz-agent/internal/regobuiltins"
	"authz-agent/internal/regogen/spectables"
)

// pipTableFile holds the state each source reads for each response class.
const pipTableFile = "testdata/pip-response-classes.txt"

// pipTableKnown lists the cells of pipTableFile the agent does not read yet,
// by "<class> <source>". The file holds the state the cell must have; the
// agent's state today is logged.
var pipTableKnown = map[string]string{
	"body/not-json GENERAL":        f11,
	"body/not-json FILTERED":       f11,
	"body/not-json jsonPath":       f11,
	"body/truncated GENERAL":       f11,
	"body/truncated FILTERED":      f11,
	"body/truncated jsonPath":      f11,
	"body/whitespace GENERAL":      f11,
	"body/whitespace FILTERED":     f11,
	"body/whitespace jsonPath":     f11,
	"body/whitespace entitlements": f11,
	"encoding/br GENERAL":          f16,
	"encoding/br FILTERED":         f16,
	"encoding/br jsonPath":         f16,
	"encoding/deflate GENERAL":     f16,
	"encoding/deflate FILTERED":    f16,
	"encoding/deflate jsonPath":    f16,
	"encoding/x-gzip GENERAL":      f16,
	"encoding/x-gzip FILTERED":     f16,
	"encoding/x-gzip jsonPath":     f16,
	"encoding/x-unknown GENERAL":   f16,
	"encoding/x-unknown FILTERED":  f16,
	"encoding/x-unknown jsonPath":  f16,
}

// pipEncodingKnown lists the sources and content codings that break
// TestPIPResponse_AnEncodedBodyReadsAsItsIdentityOrAsError, by
// "<source>/<coding>".
var pipEncodingKnown = map[string]string{
	"GENERAL/br":         f16,
	"GENERAL/deflate":    f16,
	"GENERAL/x-gzip":     f16,
	"GENERAL/x-unknown":  f16,
	"FILTERED/br":        f16,
	"FILTERED/deflate":   f16,
	"FILTERED/x-gzip":    f16,
	"FILTERED/x-unknown": f16,
	"jsonPath/br":        f16,
	"jsonPath/deflate":   f16,
	"jsonPath/x-gzip":    f16,
	"jsonPath/x-unknown": f16,
}

// pipUnreadableKnown lists the sources and bodies that break
// TestPIPResponse_BytesThatAreNotJSONReadAsError, by "<source>/<body>".
var pipUnreadableKnown = map[string]string{
	"GENERAL/text":             f11,
	"GENERAL/html":             f11,
	"GENERAL/open-brace":       f11,
	"GENERAL/truncated-array":  f11,
	"GENERAL/space":            f11,
	"GENERAL/crlf":             f11,
	"GENERAL/binary":           f11,
	"GENERAL/single-quoted":    f11,
	"GENERAL/NaN":              f11,
	"GENERAL/trailing-text":    f11,
	"FILTERED/text":            f11,
	"FILTERED/html":            f11,
	"FILTERED/open-brace":      f11,
	"FILTERED/truncated-array": f11,
	"FILTERED/space":           f11,
	"FILTERED/crlf":            f11,
	"FILTERED/binary":          f11,
	"FILTERED/single-quoted":   f11,
	"FILTERED/NaN":             f11,
	"FILTERED/trailing-text":   f11,
	"jsonPath/text":            f11,
	"jsonPath/html":            f11,
	"jsonPath/open-brace":      f11,
	"jsonPath/truncated-array": f11,
	"jsonPath/space":           f11,
	"jsonPath/crlf":            f11,
	"jsonPath/binary":          f11,
	"jsonPath/single-quoted":   f11,
	"jsonPath/NaN":             f11,
	"jsonPath/trailing-text":   f11,
	"entitlements/space":       f11,
	"entitlements/crlf":        f11,
}

const (
	f11 = "F11: a 200 answer of a PIP or of the entitlements service whose non-empty body is not JSON " +
		"reads as a null or empty source, " +
		"so a DENY over that source does not fire"
	f16 = "F16: a PIP answer in a content coding other than gzip reads as a text body, then as a null source, " +
		"so a caller's Accept-Encoding can switch off a DENY over that source"
)

// pipSource is a source whose answer the agent reads: a GENERAL or FILTERED
// PIP, the entitlements service, or the permission scope.
type pipSource struct {
	name string
	// answer is a body the source reads as a value.
	answer string
	// read calls the source under base, the URL setting of the source, with
	// calls that time out after timeout, and returns the state it reads. An
	// empty base leaves the setting empty.
	read func(t *testing.T, base string, timeout time.Duration) string
}

func pipSources() []pipSource {
	return []pipSource{
		{"GENERAL", `["x"]`, readPIPSource(policyir.PIPGeneral, "")},
		{"FILTERED", `["x"]`, readPIPSource(policyir.PIPFiltered, "")},
		{"jsonPath", `{"v": ["x"]}`, readPIPSource(policyir.PIPGeneral, "$.v")},
		{"entitlements", `{"entitlements": [{"resourceType": "doc", "references": [{"name": "r",
			"resources": [{"resourceId": "x"}]}]}]}`, readEntitlements},
		{"scope", `{"permissionScope": [{"policies": [{"scopeItems": [{"key": "domain",
			"values": [{"id": "x"}]}]}]}]}`, readPermissionScope},
	}
}

// sourceContext returns the context of one decision request whose calls
// time out after timeout.
func sourceContext(timeout time.Duration) context.Context {
	h := &regobuiltins.HTTP{Client: &http.Client{}, Token: own, Timeout: timeout}
	return regobuiltins.WithCalls(h.Context(context.Background()))
}

// readPIPSource reads the PIP subject.g of type typ and jsonPath jp the way
// its generated function does: the request of pipCall, nc.http.send, then
// pipResolve. The PIP forwards the caller's Accept-Encoding, which names
// gzip, deflate, and br.
func readPIPSource(typ policyir.PIPType, jp string) func(*testing.T, string, time.Duration) string {
	return func(t *testing.T, base string, timeout time.Duration) string {
		t.Helper()
		decl := &policyir.PIP{Name: "subject.g", Type: typ, Headers: "Accept-Encoding"}
		if jp != "" {
			decl.ReturnType, decl.JSONPath = "JSON", jp
		}
		if base != "" {
			decl.URL = base + "/pip/${subject.id}"
		}
		path, err := pipPath(decl)
		if err != nil {
			t.Fatalf("pipPath: %v", err)
		}
		req := &Request{Values: subjectValues(t, `"u1"`),
			Headers: map[string]string{"accept-encoding": "gzip, deflate, br"}}
		q := pipCall(&Ref{pip: decl}, req, func(string) (*policyir.PIP, bool) { return nil, false })
		if st := q.Get(ast.StringTerm(queryState)); st != nil {
			return string(st.Value.(ast.String))
		}
		ctx := sourceContext(timeout)
		resp, err := regobuiltins.Send(ctx, q)
		if err != nil {
			t.Fatalf("nc.http.send(%v): %v", q, err)
		}
		r, err := pipResolve(rego.BuiltinContext{Context: ctx}, resp, path)
		if err != nil {
			t.Fatalf("pipResolve: %v", err)
		}
		return resolvedText(r)
	}
}

// readEntitlements reads subject.entitledResources.of("doc").as("r") with
// the request of entCall, nc.http.send, then entResolve.
func readEntitlements(t *testing.T, base string, timeout time.Duration) string {
	t.Helper()
	q := entCall(&Request{Values: subjectValues(t, `"u1"`), Entitlements: base})
	if st := q.Get(ast.StringTerm(queryState)); st != nil {
		return string(st.Value.(ast.String))
	}
	resp, err := regobuiltins.Send(sourceContext(timeout), q)
	if err != nil {
		t.Fatalf("nc.http.send(%v): %v", q, err)
	}
	return resolvedText(entResolve(resp, "doc", []string{"r"}))
}

// readPermissionScope reads the permission scope with ReadScope and returns
// ERROR when it fails, or PASSES and the value of the key domain in each
// pass.
func readPermissionScope(t *testing.T, base string, timeout time.Duration) string {
	t.Helper()
	url := ""
	if base != "" {
		url = base + "/scope"
	}
	s := scopeModule(t, url).ReadScope(sourceContext(timeout), &Request{Values: subjectValues(t, `"u1"`)})
	if s.Failed {
		return string(spectables.StateError)
	}
	passes := make([]string, len(s.Passes))
	for i, p := range s.Passes {
		passes[i] = resolvedText(p[`["subj","permissionScope.domain"]`])
	}
	return "PASSES [" + strings.Join(passes, ", ") + "]"
}

func resolvedText(r Resolved) string {
	if r.Value == nil {
		return string(r.State)
	}
	return string(r.State) + " " + jsonText(r.Value)
}

// serve starts a server that answers every request with h.
func serve(t *testing.T, h http.HandlerFunc) string {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv.URL
}

// answering returns a server that answers status, the header
// Content-Encoding of coding unless it is "", and body.
func answering(t *testing.T, status int, coding string, body []byte) string {
	t.Helper()
	return serve(t, func(w http.ResponseWriter, _ *http.Request) {
		if coding != "" {
			w.Header().Set("Content-Encoding", coding)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write(body)
	})
}

// encode returns body in the content coding c. x-unknown stands for a
// coding the agent cannot know: every byte inverted.
func encode(t *testing.T, c string, body []byte) []byte {
	t.Helper()
	var b bytes.Buffer
	switch c {
	case "identity":
		return body
	case "gzip", "x-gzip":
		w := gzip.NewWriter(&b)
		_, _ = w.Write(body)
		_ = w.Close()
	case "deflate":
		// RFC 9110 deflate is the zlib format
		w := zlib.NewWriter(&b)
		_, _ = w.Write(body)
		_ = w.Close()
	case "br":
		return brotliStored(t, body)
	case "x-unknown":
		for _, x := range body {
			b.WriteByte(^x)
		}
	default:
		t.Fatalf("no content coding %q", c)
	}
	return b.Bytes()
}

// brotliStored returns body as a brotli stream (RFC 7932) of one
// uncompressed meta-block. Its first three bytes hold, from the low bit up:
// WBITS 0 (a 2^16 window), ISLAST 0, MNIBBLES 0 (a length of four nibbles),
// MLEN-1 in 16 bits, and ISUNCOMPRESSED 1. The body follows, then 0x03, an
// empty last meta-block.
func brotliStored(t *testing.T, body []byte) []byte {
	t.Helper()
	if len(body) == 0 {
		return []byte{0x06} // ISLAST 1, ISLASTEMPTY 1
	}
	if len(body) > 1<<16 {
		t.Fatalf("brotliStored takes at most 65536 bytes, got %d", len(body))
	}
	h := (len(body)-1)<<4 | 1<<20
	return append(append([]byte{byte(h), byte(h >> 8), byte(h >> 16)}, body...), 0x03)
}

// pipCodings are the content codings an answer is served in, besides none.
var pipCodings = []string{"identity", "gzip", "x-gzip", "deflate", "br", "x-unknown"}

// pipClass is a response class: what serves the answer of a source, or the
// URL setting a configuration class gives it.
type pipClass struct {
	name string
	base func(t *testing.T, s pipSource) string
	// timeout bounds each call, zero for [regobuiltins.DefaultTimeout].
	timeout time.Duration
}

func pipClasses() []pipClass {
	status := func(code int) func(*testing.T, pipSource) string {
		return func(t *testing.T, s pipSource) string { return answering(t, code, "", []byte(s.answer)) }
	}
	body := func(text string) func(*testing.T, pipSource) string {
		return func(t *testing.T, _ pipSource) string { return answering(t, http.StatusOK, "", []byte(text)) }
	}
	classes := []pipClass{
		{name: "config/url-empty", base: func(*testing.T, pipSource) string { return "" }},
		{name: "config/url-unusable", base: func(*testing.T, pipSource) string { return "http://bad host" }},
		{name: "transport/timeout", timeout: 100 * time.Millisecond, base: func(t *testing.T, _ pipSource) string {
			release := make(chan struct{})
			url := serve(t, func(_ http.ResponseWriter, r *http.Request) {
				select {
				case <-r.Context().Done():
				case <-release:
				}
			})
			// runs before the server's Close, which waits for the handler
			t.Cleanup(func() { close(release) })
			return url
		}},
		{name: "transport/connection-refused", base: func(t *testing.T, _ pipSource) string {
			l, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("listen: %v", err)
			}
			_ = l.Close()
			return "http://" + l.Addr().String()
		}},
		{name: "transport/reset-mid-body", base: func(t *testing.T, s pipSource) string {
			return serve(t, func(w http.ResponseWriter, _ *http.Request) {
				conn, rw, err := w.(http.Hijacker).Hijack()
				if err != nil {
					return
				}
				_, _ = fmt.Fprintf(rw, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s", len(s.answer)+100, s.answer)
				_ = rw.Flush()
				_ = conn.Close()
			})
		}},
		{name: "status/200", base: status(http.StatusOK)},
		{name: "status/201", base: status(http.StatusCreated)},
		{name: "status/204", base: status(http.StatusNoContent)},
		{name: "status/302-with-location", base: func(t *testing.T, s pipSource) string {
			target := answering(t, http.StatusOK, "", []byte(s.answer))
			return serve(t, func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, target+r.URL.Path, http.StatusFound)
			})
		}},
		{name: "status/302-without-location", base: status(http.StatusFound)},
		{name: "status/404", base: status(http.StatusNotFound)},
		{name: "status/500", base: status(http.StatusInternalServerError)},
		{name: "body/empty", base: body("")},
		{name: "body/whitespace", base: body(" \n\t ")},
		{name: "body/not-json", base: body("<html>down</html>")},
		{name: "body/truncated", base: func(t *testing.T, s pipSource) string {
			return answering(t, http.StatusOK, "", []byte(s.answer[:len(s.answer)-1]))
		}},
		{name: "body/8MiB", base: func(t *testing.T, s pipSource) string {
			// the answer, then whitespace up to the limit
			return answering(t, http.StatusOK, "", []byte(s.answer+strings.Repeat(" ", 8<<20-len(s.answer))))
		}},
		{name: "body/over-8MiB", base: func(t *testing.T, s pipSource) string {
			// the answer, which reads as a value, then whitespace past the limit
			return answering(t, http.StatusOK, "", []byte(s.answer+strings.Repeat(" ", 8<<20)))
		}},
	}
	for _, text := range []string{`null`, `false`, `true`, `0`, `1`, `""`, `"x"`, `[]`, `["x"]`, `{}`, `{"k": "v"}`} {
		classes = append(classes, pipClass{name: "body/" + strings.ReplaceAll(text, " ", ""), base: body(text)})
	}
	for _, c := range pipCodings {
		classes = append(classes, pipClass{name: "encoding/" + c, base: func(t *testing.T, s pipSource) string {
			return answering(t, http.StatusOK, c, encode(t, c, []byte(s.answer)))
		}})
	}
	classes = append(classes, pipClass{name: "encoding/gzip-over-8MiB", base: func(t *testing.T, s pipSource) string {
		// small on the wire, over the limit once decompressed
		return answering(t, http.StatusOK, "gzip", encode(t, "gzip", []byte(s.answer+strings.Repeat(" ", 8<<20))))
	}})
	return classes
}

// TestPIPResponse_EachClassReadsToTheStateOfItsCell drives the call of each
// source against a server that answers in each response class, and
// compares the state the agent reads with the cell of pipTableFile. A
// changed cell changes what a deployed policy decides: list it among the
// breaking changes. REGOGEN_UPDATE_PIP_TABLE=1 rewrites the file from the
// states read, except the cells pipTableKnown lists.
func TestPIPResponse_EachClassReadsToTheStateOfItsCell(t *testing.T) {
	got := map[string]string{}
	for _, c := range pipClasses() {
		for _, s := range pipSources() {
			got[c.name+" "+s.name] = s.read(t, c.base(t, s), c.timeout)
		}
	}
	want := readPIPTable(t)
	if os.Getenv("REGOGEN_UPDATE_PIP_TABLE") == "1" {
		for k := range pipTableKnown {
			w, ok := want[k]
			if !ok {
				t.Fatalf("%s is listed in pipTableKnown and has no cell in %s; write the state it must read by hand",
					k, pipTableFile)
			}
			got[k] = w
		}
		writePIPTable(t, got)
		return
	}
	for _, k := range slices.Sorted(mapKeys(got)) {
		w, ok := want[k]
		switch why, known := pipTableKnown[k]; {
		case !ok:
			t.Errorf("%s reads %s, and %s has no cell for it; rerun with REGOGEN_UPDATE_PIP_TABLE=1", k, got[k], pipTableFile)
		case got[k] != w && known:
			t.Logf("known violation %s (%s): reads %s, want %s", k, why, got[k], w)
		case got[k] != w:
			t.Errorf("%s reads %s, want %s", k, got[k], w)
		case known:
			t.Errorf("%s reads %s as its cell says: remove its entry from pipTableKnown", k, w)
		}
	}
	for _, k := range slices.Sorted(mapKeys(pipTableKnown)) {
		if _, ok := got[k]; !ok {
			t.Errorf("%s is listed in pipTableKnown, and no source or class makes it: remove its entry", k)
		}
	}
	for _, k := range slices.Sorted(mapKeys(want)) {
		if _, ok := got[k]; !ok {
			t.Errorf("%s has a cell %s, and no source or class makes it; remove it from %s", k, want[k], pipTableFile)
		}
	}
}

func readPIPTable(t *testing.T) map[string]string {
	t.Helper()
	f, err := os.Open(pipTableFile)
	if os.IsNotExist(err) {
		return map[string]string{}
	}
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = f.Close() }()
	out := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) == 0 || strings.HasPrefix(fields[0], "#") {
			continue
		}
		if len(fields) < 3 {
			t.Fatalf("%s: line %q is not <class> <source> <state>", pipTableFile, sc.Text())
		}
		out[fields[0]+" "+fields[1]] = strings.Join(fields[2:], " ")
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("read %s: %v", pipTableFile, err)
	}
	return out
}

func writePIPTable(t *testing.T, cells map[string]string) {
	t.Helper()
	var b strings.Builder
	b.WriteString("# The state each source reads for each class of the answer of its service:\n" +
		"# <class> <source> <state>. TestPIPResponse_EachClassReadsToTheStateOfItsCell\n" +
		"# compares the agent with it; REGOGEN_UPDATE_PIP_TABLE=1 rewrites it.\n" +
		"# A changed cell changes what a deployed policy decides. An encoding cell\n" +
		"# of ERROR may become the status/200 state once the agent decodes that coding.\n")
	for _, c := range pipClasses() {
		b.WriteString("\n")
		for _, s := range pipSources() {
			fmt.Fprintf(&b, "%-30s %-13s %s\n", c.name, s.name, cells[c.name+" "+s.name])
		}
	}
	if err := os.WriteFile(pipTableFile, []byte(b.String()), 0o600); err != nil {
		t.Fatalf("write %s: %v", pipTableFile, err)
	}
}

// pipBodies are bodies of every JSON type, of zero bytes, and not JSON.
var pipBodies = []string{"", `null`, `false`, `true`, `0`, `1`, `""`, `"x"`, `[]`, `["x"]`, `{}`, `{"k": "v"}`,
	`{"v": ["x"]}`, " \n", "<html>down</html>", `["x"`}

// A body served in a content coding reads to the state the same body reads
// to without one, or to ERROR: the coding cannot turn a value into another
// value or into a null source.
func TestPIPResponse_AnEncodedBodyReadsAsItsIdentityOrAsError(t *testing.T) {
	seen := map[string][]string{}
	for _, s := range pipSources() {
		bodies := pipBodies
		if !slices.Contains(bodies, s.answer) {
			bodies = append(slices.Clone(bodies), s.answer)
		}
		for _, text := range bodies {
			plain := s.read(t, answering(t, http.StatusOK, "", []byte(text)), 0)
			for _, c := range pipCodings {
				got := s.read(t, answering(t, http.StatusOK, c, encode(t, c, []byte(text))), 0)
				if got != plain && got != string(spectables.StateError) {
					k := s.name + "/" + c
					seen[k] = append(seen[k], fmt.Sprintf("%q reads %s, and %s without a coding", text, got, plain))
				}
			}
		}
	}
	checkKnown(t, "pipEncodingKnown", pipEncodingKnown, seen)
}

// pipNotJSON are bodies that are not empty and are not JSON.
var pipNotJSON = []struct{ name, text string }{
	{"text", `x`},
	{"html", `<html>down</html>`},
	{"open-brace", `{`},
	{"truncated-array", `["x"`},
	{"space", ` `},
	{"crlf", "\r\n"},
	{"binary", "\x00\xff"},
	{"single-quoted", `'x'`},
	{"NaN", `NaN`},
	{"trailing-text", `{"k": "v"} x`},
}

// A 200 answer whose bytes are not empty and are not JSON reads as ERROR in
// every source.
func TestPIPResponse_BytesThatAreNotJSONReadAsError(t *testing.T) {
	seen := map[string][]string{}
	for _, s := range pipSources() {
		for _, b := range pipNotJSON {
			if got := s.read(t, answering(t, http.StatusOK, "", []byte(b.text)), 0); got != string(spectables.StateError) {
				k := s.name + "/" + b.name
				seen[k] = append(seen[k], fmt.Sprintf("%q reads %s", b.text, got))
			}
		}
	}
	checkKnown(t, "pipUnreadableKnown", pipUnreadableKnown, seen)
}

// checkKnown fails t for each key of seen that known does not list, and for
// each key of known that seen does not hold; it logs the rest.
func checkKnown(t *testing.T, name string, known map[string]string, seen map[string][]string) {
	t.Helper()
	for _, k := range slices.Sorted(mapKeys(seen)) {
		if why, ok := known[k]; ok {
			t.Logf("known violation %s (%s):\n\t%s", k, why, strings.Join(seen[k], "\n\t"))
			continue
		}
		t.Errorf("%s:\n\t%s", k, strings.Join(seen[k], "\n\t"))
	}
	for _, k := range slices.Sorted(mapKeys(known)) {
		if _, ok := seen[k]; !ok {
			t.Errorf("%s holds now: remove its entry from %s", k, name)
		}
	}
}
