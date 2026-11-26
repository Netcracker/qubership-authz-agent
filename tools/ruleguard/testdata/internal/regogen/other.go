package regogen

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"hash/fnv"
	"io"
	"regexp"
	"strings"
)

func recordElsewhere() (Record, *Record) {
	var r Record
	r.State = "VALUE" // want `a Record is built only by record in project.go`
	p := &Record{}    // want `a Record is built only by record in project.go`
	p.Value = 1       // want `a Record is built only by record in project.go`
	return r, p
}

type tree struct{}

func (tree) String() string { return "" }
func (tree) Dump() string   { return "" }

func textAsIdentity(t tree, v any, m map[string]int, s string) {
	_ = sha256.Sum256([]byte(t.Dump()))              // want `t.Dump\(\) is text for people`
	_ = sha256.Sum256([]byte(fmt.Sprint(v)))         // want `fmt renders text for people`
	_ = sha256.Sum256([]byte(fmt.Sprintf("%+v", v))) // want `fmt renders text for people`
	h := fnv.New64()
	_, _ = h.Write([]byte(t.String()))           // want `t.String\(\) is text for people`
	_, _ = h.Write([]byte(fmt.Sprintf("%v", v))) // want `fmt renders text for people`
	_, _ = io.WriteString(h, t.String())         // want `t.String\(\) is text for people`
	_, _ = fmt.Fprint(h, v)                      // want `fmt renders text for people`
	_, _ = fmt.Fprintf(h, "%#v", v)              // want `fmt renders text for people`
	_ = m[t.String()]                            // want `t.String\(\) is text for people`
	_ = m[fmt.Sprint(v)]                         // want `fmt renders text for people`
	_ = m[fmt.Sprintf("%v", v)]                  // want `fmt renders text for people`
	_ = map[string]int{"a": 1, t.String(): 2}    // want `t.String\(\) is text for people`
	_ = t.Dump() == s                            // want `t.Dump\(\) is text for people`
	_ = s != t.String()                          // want `t.String\(\) is text for people`
	_ = fmt.Sprint(v) == s                       // want `fmt renders text for people`
	_ = fmt.Sprintf("%v", v) != s                // want `fmt renders text for people`

	// The text of a buffer is its content, and %d prints a number the
	// same way every time: neither is reported.
	var b bytes.Buffer
	var sb strings.Builder
	_ = b.String() == s
	_ = sb.String() == s
	_ = fmt.Sprintf("%d", 1) == s
	_ = m[fmt.Sprintf("%s/%s", s, s)]
}

func pathText(p string) {
	_ = regexp.MustCompile(`^\$\['([^']*)'\]`) // want `a jsonPath bracket step is read by internal/jsonpath only`
	_ = strings.HasPrefix(p, "$['")            // want `a jsonPath bracket step is read by internal/jsonpath only`
	_ = strings.TrimPrefix(p, `['`)            // want `a jsonPath bracket step is read by internal/jsonpath only`
	_, _, _ = strings.Cut(p, "['")             // want `a jsonPath bracket step is read by internal/jsonpath only`
	_ = strings.SplitN(p, "$['", 2)            // want `a jsonPath bracket step is read by internal/jsonpath only`

	// A dotted path and a bracket not at the start are not bracket text.
	_ = strings.HasPrefix(p, "$.")
	_ = strings.Contains(p, "a['")
}
