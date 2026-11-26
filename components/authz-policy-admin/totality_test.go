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

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"authz-agent/internal/policyir"
	"authz-agent/internal/regogen"
	"authz-agent/internal/regogen/spectables"
)

// knownTotalityViolations maps a violation of
// TestEveryUploadTheAdminAcceptsLoadsInTheAgent, written as the outcome and
// the spellings that cause it, to the finding ID and the defect in one
// phrase. A fix of the defect removes the entry.
var knownTotalityViolations = map[string]string{
	"the export reader refuses the tenant: resourceType=all":                                           knownF31,
	"the export reader refuses the tenant: resourceType=All":                                           knownF31,
	"the export reader refuses the tenant: resourceType=*":                                             knownF31,
	"Generate refuses the tenant: pip jsonPath=a bracketed key with a space + condition=reads the PIP": knownF28,
	"GenerateFilter fails: pip jsonPath=a bracketed key with a space + condition=reads the PIP":        knownF28,
	"the tree loses the predicate: predicates=mongodbPredicate number":                                 knownF29,
	"the tree loses the predicate: predicates=mongodbPredicate object":                                 knownF29,
	"the tree loses the predicate: predicates=mongodbPredicate list":                                   knownF29,
	"the tree loses the predicate: predicates=mongodbPredicate boolean":                                knownF29,
	"the tree loses the predicate: a top-level mongodbPredicate":                                       knownF29,
}

const (
	knownF31 = "F31: the admin checks that a policy is global only for the resourceType ALL, so it accepts " +
		"all, All, or * on a policy that is not global, and the agent refuses the whole tenant on the next export"
	knownF28 = "F28: the admin accepts a jsonPath it never parses, and the agent refuses the tenant whose " +
		"condition reads a PIP with a bracketed key that holds a space"
	knownF29 = "F29: the admin accepts a mongodbPredicate that is not a text, or one written beside " +
		"predicates, and the export leaves the predicate out"
)

// carried is what an upload carries that the tree of the agent must keep.
type carried int

const (
	carriesNothing carried = iota
	carriesCondition
	carriesPredicate
)

// spelling is one way an upload writes one field.
type spelling struct {
	// class names the spelling in a violation key.
	class string
	// value is the JSON value of the field, or "" to leave the field out.
	value   string
	carries carried
	// with sets other fields of the same object, for a spelling that the
	// admin accepts only together with them; an empty value removes the
	// field. It wins over the spelling of the field it sets.
	with map[string]string
}

// The spellings of each field the admin binds. Every field of
// policyFieldKinds and pipFieldKinds has an entry, and the first spelling of
// each is the base value of the field.
var (
	policySpellings = map[string][]spelling{
		"resourceType": {
			{class: "a type", value: `"Doc"`},
			{class: "ALL", value: `"ALL"`},
			{class: "all", value: `"all"`},
			{class: "All", value: `"All"`},
			{class: "*", value: `"*"`},
			{class: "ALL padded with spaces", value: `" ALL "`},
			{class: "a number", value: `5`},
		},
		"component": {
			{class: "a component", value: `"C"`},
			{class: "ALL", value: `"ALL"`},
		},
		"operation": {
			{class: "an operation", value: `"READ"`},
			{class: "ALL", value: `"ALL"`},
		},
		"predicates": {
			{class: "absent"},
			{class: "null", value: `null`},
			{class: "a text", value: `"{\"a\": 1}"`, carries: carriesPredicate},
			{class: "mongodbPredicate text", value: `{"mongodbPredicate": "{\"a\": 1}"}`, carries: carriesPredicate},
			{class: "mongodbPredicate number", value: `{"mongodbPredicate": 5}`, carries: carriesPredicate},
			{class: "mongodbPredicate object", value: `{"mongodbPredicate": {"a": 1}}`, carries: carriesPredicate},
			{class: "mongodbPredicate list", value: `{"mongodbPredicate": [1]}`, carries: carriesPredicate},
			{class: "mongodbPredicate boolean", value: `{"mongodbPredicate": true}`, carries: carriesPredicate},
		},
		"condition": {
			{class: "absent"},
			{class: "empty", value: `""`},
			{class: "spaces", value: `"   "`},
			{class: "a tab", value: `"\t"`},
			{class: "a no-break space", value: `"\u00a0"`},
			{class: "reads the PIP", value: `"subject.g == 'x'"`, carries: carriesCondition},
			{class: "reads the resource", value: `"resource.a == 'x'"`, carries: carriesCondition},
			{class: "reads an index of the roles", value: `"subject.roles[0] == 'admin'"`, carries: carriesCondition},
			{class: "reads an undeclared subject attribute", value: `"subject.nope == 'x'"`, carries: carriesCondition},
		},
		"rsqlPredicate": {
			{class: "absent"},
			{class: "a text", value: `"a==1"`, carries: carriesPredicate},
		},
		"roles": {
			{class: "one role", value: `["R"]`},
			{class: "two roles", value: `["R", "S"]`},
		},
		"reason": {
			{class: "absent"},
			{class: "a text", value: `"why"`},
		},
		"id": {
			{class: "absent"},
			{class: "a UUID", value: `"0b5e6f9c-3c1d-4f6e-9a2b-1c2d3e4f5a6b"`},
			{class: "a text that is not a UUID", value: `"p1"`},
		},
		"applicableForFrontend": {
			{class: "absent"},
			{class: "true", value: `true`},
			{class: "TRUE as a text", value: `"TRUE"`},
		},
	}
	pipSpellings = map[string][]spelling{
		"name": {{class: "subject.g", value: `"subject.g"`}},
		"pipType": {
			{class: "GENERAL", value: `"GENERAL"`},
			{class: "GENERAL padded with spaces", value: `" GENERAL "`},
			{class: "FILTERED", value: `"FILTERED"`, with: map[string]string{
				"resourceType": `"Doc"`, "type": `"REGULAR"`, "jsonPath": ""}},
			{class: "HEADER", value: `"HEADER"`, with: map[string]string{
				"header": `"X-G"`, "url": "", "type": `"REGULAR"`, "jsonPath": ""}},
			{class: "TOKEN", value: `"TOKEN"`, with: map[string]string{
				"claim": `"g"`, "url": "", "type": `"REGULAR"`, "jsonPath": ""}},
			{class: "MAPPING", value: `"MAPPING"`, with: map[string]string{
				"name": `"subject.permissions"`, "productMapping": `{"subject.roles": {"R": "p"}}`,
				"url": "", "type": `"REGULAR"`, "jsonPath": ""}},
			{class: "PERMISSION_SCOPE", value: `"PERMISSION_SCOPE"`, with: map[string]string{
				"name": `"subject.permissionScope"`, "type": `"REGULAR"`, "jsonPath": ""}},
		},
		"type": {
			{class: "JSON", value: `"JSON"`},
			{class: "REGULAR", value: `"REGULAR"`},
			{class: "REGULAR without a jsonPath", value: `"REGULAR"`, with: map[string]string{"jsonPath": ""}},
			{class: "UUID", value: `"UUID"`, with: map[string]string{"jsonPath": ""}},
			{class: "JSON padded with spaces", value: `" JSON "`},
			{class: "absent", with: map[string]string{"jsonPath": ""}},
		},
		"url": {{class: "a URL", value: `"http://pip/g"`}},
		"jsonPath": {
			{class: "a dotted path", value: `"$.v"`},
			{class: "a bracketed key with a space", value: `"$['a b']"`},
			{class: "a recursive descent", value: `"$..v"`},
			{class: "a slice of every element", value: `"$.l[:]"`},
			{class: "an index beyond a 64-bit integer", value: `"$.l[99999999999999999999]"`},
		},
		"httpMethod": {
			{class: "absent"},
			{class: "GET", value: `"GET"`},
			{class: "POST", value: `"POST"`},
		},
		"description": {
			{class: "absent"},
			{class: "a text", value: `"d"`},
		},
		"cacheable": {
			{class: "absent"},
			{class: "true", value: `true`},
		},
		"cachePeriod": {
			{class: "absent"},
			{class: "a number", value: `60`},
		},
		"defaultValue": {
			{class: "absent"},
			{class: "a text", value: `"x"`},
		},
		"headers": {
			{class: "absent"},
			{class: "a header name", value: `"X-Trace"`},
		},
		"deprecated": {
			{class: "absent"},
			{class: "false", value: `false`},
		},
		"requestAttributes": {{class: "absent"}},
		"beanName":          {{class: "absent"}},
		"header":            {{class: "absent"}},
		"claim":             {{class: "absent"}},
		"productMapping":    {{class: "absent"}},
		"customMapping":     {{class: "absent"}},
		"resourceType":      {{class: "absent"}},
	}
	// refusedSpellings are the spellings that no upload of the corpus the
	// admin accepts holds. The totality test checks nothing about them, so
	// a spelling lands here only where the admin refuses it on purpose.
	refusedSpellings = []string{
		"condition=a no-break space", "condition=a tab", "condition=empty", "condition=spaces", "id=a text that is not a UUID",
	}
	// crossedPolicyFields are the policy fields whose spellings the corpus
	// takes in every combination, because whether a policy is global turns
	// on several of them at once. Every other field varies alone.
	crossedPolicyFields = []string{"resourceType", "component", "operation", "predicates", "condition"}
	// topLevelMongoDB spells a mongodbPredicate written beside predicates
	// instead of inside it, which no field of policyFieldKinds names.
	topLevelMongoDB = spelling{class: "a top-level mongodbPredicate", value: `"{\"a\": 1}"`, carries: carriesPredicate}
)

// upload is one PIP declaration and one simplified policy, each as the
// spelling index of every field.
type upload struct {
	pip, policy map[string]int
	// topLevel adds topLevelMongoDB to the policy.
	topLevel bool
}

func (u upload) clone() upload {
	return upload{pip: maps.Clone(u.pip), policy: maps.Clone(u.policy), topLevel: u.topLevel}
}

// key identifies the upload for the cache of outcomes.
func (u upload) key() string {
	return fmt.Sprint(u.pip, u.policy, u.topLevel)
}

// nonBase is the spellings of u other than the base ones, as field=class.
func (u upload) nonBase() []string {
	var out []string
	for _, f := range slices.Sorted(maps.Keys(u.pip)) {
		if i := u.pip[f]; i != 0 {
			out = append(out, "pip "+f+"="+pipSpellings[f][i].class)
		}
	}
	for _, f := range slices.Sorted(maps.Keys(u.policy)) {
		if i := u.policy[f]; i != 0 {
			out = append(out, f+"="+policySpellings[f][i].class)
		}
	}
	if u.topLevel {
		out = append(out, topLevelMongoDB.class)
	}
	return out
}

// revert returns u with the spelling named by nonBase entry s set back to
// the base one.
func (u upload) revert(s string) upload {
	r := u.clone()
	if s == topLevelMongoDB.class {
		r.topLevel = false
		return r
	}
	field, _, _ := strings.Cut(strings.TrimPrefix(s, "pip "), "=")
	if strings.HasPrefix(s, "pip ") {
		r.pip[field] = 0
	} else {
		r.policy[field] = 0
	}
	return r
}

// only returns the base upload with the spelling named by nonBase entry s
// of u.
func (u upload) only(s string) upload {
	r := baseUpload()
	if s == topLevelMongoDB.class {
		r.topLevel = true
		return r
	}
	field, _, _ := strings.Cut(strings.TrimPrefix(s, "pip "), "=")
	if strings.HasPrefix(s, "pip ") {
		r.pip[field] = u.pip[field]
	} else {
		r.policy[field] = u.policy[field]
	}
	return r
}

func (u upload) carries(c carried) bool {
	for f, i := range u.policy {
		if policySpellings[f][i].carries == c {
			return true
		}
	}
	return c == carriesPredicate && u.topLevel
}

// objectFields returns the fields of one JSON object, as raw JSON values,
// from their spellings.
func objectFields(spellings map[string][]spelling, chosen map[string]int) map[string]string {
	fields := map[string]string{}
	for f, i := range chosen {
		if s := spellings[f][i]; s.value != "" {
			fields[f] = s.value
		}
	}
	for f, i := range chosen {
		for g, v := range spellings[f][i].with {
			if v == "" {
				delete(fields, g)
			} else {
				fields[g] = v
			}
		}
	}
	return fields
}

// renderObject renders the fields of one JSON object from their spellings.
func renderObject(spellings map[string][]spelling, chosen map[string]int, extra ...string) string {
	fields := objectFields(spellings, chosen)
	var parts []string
	for _, f := range slices.Sorted(maps.Keys(fields)) {
		parts = append(parts, fmt.Sprintf("%q: %s", f, fields[f]))
	}
	return "{" + strings.Join(append(parts, extra...), ", ") + "}"
}

func (u upload) bodies() (pips, policies string) {
	var extra []string
	if u.topLevel {
		extra = append(extra, `"mongodbPredicate": `+topLevelMongoDB.value)
	}
	return "[" + renderObject(pipSpellings, u.pip) + "]", "[" + renderObject(policySpellings, u.policy, extra...) + "]"
}

// baseUpload is the upload whose every field has its base spelling.
func baseUpload() upload {
	base := upload{pip: map[string]int{}, policy: map[string]int{}}
	for f := range pipSpellings {
		base.pip[f] = 0
	}
	for f := range policySpellings {
		base.policy[f] = 0
	}
	return base
}

// totalityCorpus is the uploads of TestEveryUploadTheAdminAcceptsLoadsInTheAgent:
// every combination of the spellings of crossedPolicyFields; every other
// spelling of a policy field alone, beside the base spelling of the rest;
// and every other spelling of a PIP field alone, beside a policy whose
// condition reads the PIP.
func totalityCorpus() []upload {
	base := baseUpload()
	readsPIP := base.clone()
	readsPIP.policy["condition"] = slices.IndexFunc(policySpellings["condition"],
		func(s spelling) bool { return s.class == "reads the PIP" })
	out := []upload{base}
	var cross func(u upload, fields []string)
	cross = func(u upload, fields []string) {
		if len(fields) == 0 {
			out = append(out, u)
			return
		}
		for i := range policySpellings[fields[0]] {
			v := u.clone()
			v.policy[fields[0]] = i
			cross(v, fields[1:])
		}
	}
	cross(base, crossedPolicyFields)
	for _, f := range slices.Sorted(maps.Keys(policySpellings)) {
		if slices.Contains(crossedPolicyFields, f) {
			continue
		}
		for i := 1; i < len(policySpellings[f]); i++ {
			v := base.clone()
			v.policy[f] = i
			out = append(out, v)
		}
	}
	for _, f := range slices.Sorted(maps.Keys(pipSpellings)) {
		for i := 1; i < len(pipSpellings[f]); i++ {
			v := readsPIP.clone()
			v.pip[f] = i
			out = append(out, v)
		}
	}
	v := base.clone()
	v.topLevel = true
	return append(out, v)
}

// outcome is what the agent does with one upload.
type outcome struct {
	// accepted is set when the admin answers both uploads with 2xx.
	accepted bool
	// violations maps each way the agent fails the upload to an example of
	// its error.
	violations map[string]string
}

// loadInAgent uploads u to a fresh admin and reads its export as the agent does.
func loadInAgent(u upload, tab *spectables.Table) outcome {
	st, err := newStore("")
	if err != nil {
		panic(err)
	}
	mux := http.NewServeMux()
	(&server{st: st, defaultTenantID: defaultTenant}).routes(mux)
	pips, policies := u.bodies()
	if serve(mux, http.MethodPut, pipsPath+"D", pips, "").Code/100 != 2 ||
		serve(mux, http.MethodPut, policiesPath+"D", policies, "").Code/100 != 2 {
		return outcome{}
	}
	out := outcome{accepted: true, violations: map[string]string{}}
	exp, err := policyir.FromRegular(
		serve(mux, http.MethodGet, "/access/v3/config/policySets", "", "").Body.Bytes(),
		serve(mux, http.MethodGet, "/access/v3/config/pips", "", "").Body.Bytes())
	if err != nil {
		out.violations["the export is unreadable"] = err.Error()
		return out
	}
	if e, ok := exp.Failed[defaultTenant]; ok {
		out.violations["the export reader refuses the tenant"] = e.Error()
		return out
	}
	tree := exp.Trees[defaultTenant]
	if tree == nil {
		out.violations["the export has no tree of the tenant"] = ""
		return out
	}
	if d := exp.Dropped[defaultTenant]; len(d) > 0 {
		out.violations["the export reader leaves a part out"] = d[0]
	}
	if _, err := regogen.Generate(tree, tab, regogen.DefaultOptions()); err != nil {
		if _, ok := errors.AsType[*regogen.RejectedError](err); ok {
			out.violations["Generate refuses the tenant"] = err.Error()
		} else {
			out.violations["Generate fails"] = err.Error()
		}
	}
	if _, err := regogen.GenerateFilter(tree, tab, regogen.DefaultOptions()); err != nil {
		out.violations["GenerateFilter fails"] = err.Error()
	}
	hasCondition, hasPredicate := false, false
	note := func(pr policyir.Predicates, c *policyir.Condition) {
		hasPredicate = hasPredicate || len(pr.Text) > 0 || pr.Custom != nil
		if c != nil {
			if text := policyir.FormatCondition(c); text != "" && text != "true" {
				hasCondition = true
			}
		}
	}
	for _, g := range tree.Simplified {
		for _, p := range g.Policies {
			note(p.Predicates, p.Condition)
		}
	}
	var walk func(s *policyir.PolicySet)
	walk = func(s *policyir.PolicySet) {
		for _, p := range s.Policies {
			for _, r := range p.Rules {
				note(r.Predicates, r.Condition)
			}
		}
		for _, c := range s.Sets {
			walk(c)
		}
	}
	for _, s := range tree.Sets {
		walk(s)
	}
	if lost := lostPolicyFields(u, tree); len(lost) > 0 {
		out.violations["the tree loses a policy field"] = strings.Join(lost, ", ")
	}
	if u.carries(carriesCondition) && !hasCondition {
		out.violations["the tree loses the condition"] = ""
	}
	if u.carries(carriesPredicate) && !hasPredicate {
		out.violations["the tree loses the predicate"] = ""
	}
	var name string
	if err := json.Unmarshal([]byte(objectFields(pipSpellings, u.pip)["name"]), &name); err != nil {
		panic(err)
	}
	i := slices.IndexFunc(tree.PIPs, func(p *policyir.PIP) bool { return p.Name == name })
	if i < 0 {
		out.violations["the tree loses the PIP declaration"] = ""
		return out
	}
	p := tree.PIPs[i]
	kept := map[string]string{
		"claim": p.Claim, "header": p.Header, "url": p.URL, "httpMethod": p.HTTPMethod, "jsonPath": p.JSONPath,
		"type": p.ReturnType, "headers": p.Headers, "resourceType": p.ResourceType, "defaultValue": p.DefaultValue,
	}
	for field, raw := range objectFields(pipSpellings, u.pip) {
		got, compared := kept[field]
		want := fieldText(raw)
		if field == "defaultValue" {
			want = raw
		}
		if compared && got != want {
			out.violations["the tree changes the PIP field "+field] = fmt.Sprintf("%q, want %q", got, want)
		}
	}
	return out
}

// fieldText is the text of the raw JSON value raw as the tree holds it: a
// JSON text unquoted and trimmed, anything else as written.
func fieldText(raw string) string {
	var text string
	if json.Unmarshal([]byte(raw), &text) == nil {
		return strings.TrimSpace(text)
	}
	return raw
}

// lostPolicyFields returns the policy fields of u whose value the tree does
// not hold, each as field=value. A resourceType, component, or operation is
// looked for as a quoted operand of a set, policy, or rule target, and in the
// slots of a simplified policy; a role as an operand of a policy target or in
// the roles of a simplified policy. A value the admin reads as ALL (any case
// of ALL, or *) is skipped, since a global policy holds no such operand. The
// id is not looked for: the converter merges the policies of one set and one
// role list into one policy with an ID of its own.
func lostPolicyFields(u upload, tree *policyir.Tree) []string {
	held := map[string]bool{}
	hold := func(texts ...string) {
		for _, t := range texts {
			held[t] = true
		}
	}
	var targets []string
	target := func(c *policyir.Condition) {
		if c != nil {
			targets = append(targets, policyir.FormatCondition(c))
		}
	}
	var walk func(s *policyir.PolicySet)
	walk = func(s *policyir.PolicySet) {
		hold(s.Domain)
		target(s.Target)
		for _, p := range s.Policies {
			target(p.Target)
			for _, r := range p.Rules {
				target(r.Target)
			}
		}
		for _, c := range s.Sets {
			walk(c)
		}
	}
	for _, s := range tree.Sets {
		walk(s)
	}
	for _, g := range tree.Simplified {
		hold(g.Component, g.ResourceType)
		for _, p := range g.Policies {
			hold(p.Operation)
			hold(p.Roles...)
		}
	}
	found := func(v string) bool {
		return held[v] || slices.ContainsFunc(targets, func(t string) bool { return strings.Contains(t, strconv.Quote(v)) })
	}
	fields := objectFields(policySpellings, u.policy)
	var lost []string
	for _, f := range []string{"resourceType", "component", "operation"} {
		if raw, ok := fields[f]; ok {
			if v := fieldText(raw); !strings.EqualFold(v, "ALL") && v != "*" && !found(v) {
				lost = append(lost, f+"="+v)
			}
		}
	}
	var roles []string
	if err := json.Unmarshal([]byte(fields["roles"]), &roles); err != nil {
		panic(err)
	}
	for _, r := range roles {
		if !found(r) {
			lost = append(lost, "roles="+r)
		}
	}
	return lost
}

// Every upload the admin accepts loads in the agent: the export reader keeps
// the tenant and leaves nothing out, Generate and GenerateFilter succeed, and
// the tree keeps the condition, the predicate, and the PIP the upload
// carried. A violation is reported as its outcome and the spellings without
// which the outcome goes away.
func TestEveryUploadTheAdminAcceptsLoadsInTheAgent(t *testing.T) {
	tab, err := regogen.DefaultTable()
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	cache := map[string]outcome{}
	eval := func(u upload) outcome {
		k := u.key()
		mu.Lock()
		o, ok := cache[k]
		mu.Unlock()
		if !ok {
			o = loadInAgent(u, tab)
			mu.Lock()
			cache[k] = o
			mu.Unlock()
		}
		return o
	}

	corpus := totalityCorpus()
	type found struct {
		example, err string
		count        int
	}
	violations := map[string]*found{}
	accepted := 0
	unexercised := map[string]bool{}
	for _, u := range corpus {
		for _, s := range u.nonBase() {
			unexercised[s] = true
		}
	}
	jobs := make(chan upload)
	var wg sync.WaitGroup
	for range runtime.GOMAXPROCS(0) {
		wg.Go(func() {
			for u := range jobs {
				o := eval(u)
				if !o.accepted {
					continue
				}
				mu.Lock()
				accepted++
				for _, s := range u.nonBase() {
					delete(unexercised, s)
				}
				mu.Unlock()
				for v, e := range o.violations {
					// A culprit is a spelling whose revert makes the upload
					// load cleanly or, where no revert does, one whose revert
					// removes this violation; a revert the admin refuses
					// counts as neither. Where some culprits, each alone
					// beside the base spellings, show the violation, they
					// are the key.
					var clean, removing, alone []string
					for _, s := range u.nonBase() {
						r := eval(u.revert(s))
						if _, still := r.violations[v]; !r.accepted || still {
							continue
						}
						removing = append(removing, s)
						if len(r.violations) == 0 {
							clean = append(clean, s)
						}
					}
					culprits := clean
					if len(culprits) == 0 {
						culprits = removing
					}
					for _, s := range culprits {
						if _, ok := eval(u.only(s)).violations[v]; ok {
							alone = append(alone, s)
						}
					}
					if len(alone) > 0 {
						culprits = alone
					}
					k := v + ": " + strings.Join(culprits, " + ")
					if len(culprits) == 0 {
						k = v + ": no spelling alone"
					}
					pips, policies := u.bodies()
					mu.Lock()
					if violations[k] == nil {
						violations[k] = &found{example: pips + " " + policies, err: e}
					}
					violations[k].count++
					mu.Unlock()
				}
			}
		})
	}
	for _, u := range corpus {
		jobs <- u
	}
	close(jobs)
	wg.Wait()
	t.Logf("the admin accepts %d of %d uploads", accepted, len(corpus))
	if got := slices.Sorted(maps.Keys(unexercised)); !slices.Equal(got, refusedSpellings) {
		t.Errorf("the spellings in no accepted upload are %q, want refusedSpellings %q", got, refusedSpellings)
	}

	for _, k := range slices.Sorted(maps.Keys(violations)) {
		f := violations[k]
		if known, ok := knownTotalityViolations[k]; ok {
			t.Logf("known violation, %s: %s, in %d accepted uploads", known, k, f.count)
			continue
		}
		t.Errorf("%s, in %d accepted uploads, such as %s\n    error: %s", k, f.count, f.example, f.err)
	}
	for _, k := range slices.Sorted(maps.Keys(knownTotalityViolations)) {
		if violations[k] == nil {
			t.Errorf("no accepted upload shows %q; remove its entry from knownTotalityViolations (%s)",
				k, knownTotalityViolations[k])
		}
	}
}

// The spellings cover every field the admin binds, so that a field added to
// policyFieldKinds or pipFieldKinds also gets spellings the totality test
// uploads.
func TestEveryFieldTheAdminBindsHasSpellings(t *testing.T) {
	for _, c := range []struct {
		name      string
		kinds     map[string]fieldKind
		spellings map[string][]spelling
	}{
		{"policy", policyFieldKinds, policySpellings},
		{"PIP", pipFieldKinds, pipSpellings},
	} {
		got, want := slices.Sorted(maps.Keys(c.spellings)), slices.Sorted(maps.Keys(c.kinds))
		if !slices.Equal(got, want) {
			t.Errorf("%s fields with spellings = %v, want the fields the admin binds, %v", c.name, got, want)
		}
	}
}
