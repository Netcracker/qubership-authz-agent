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
	"bufio"
	"encoding/json"
	"fmt"
	"io/fs"
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
)

// requestsWithoutAGoldenFile lists the goldens the runners compare with that
// are known not to be recorded, one <case id>/<subtest> per line.
const requestsWithoutAGoldenFile = "testdata/requests-without-a-golden.txt"

// Each golden a runner compares an answer of a case file with is recorded, or
// is listed in requests-without-a-golden.txt under the subtest that compares
// it. That covers the setup of a case (the upload of an isolated case, the
// declaration of a regular case's domain and each of its uploads), the
// requests and what their PIPs received, and every observation of a step. A
// golden that is not recorded skips as not recorded on every profile, so the
// run that misses it still passes; this test makes such a gap a failure until
// the golden is recorded or listed. A listed golden that is recorded fails as
// well, so the list shrinks as goldens are recorded. Which goldens are
// compared is read from the recorded setup, in the order of the runners
// (comparedGoldens).
func TestCaseFiles_EveryRequestHasAGolden(t *testing.T) {
	index, err := goldenIndex("testdata/golden")
	if err != nil {
		t.Fatal(err)
	}
	listed, err := readRequestList(requestsWithoutAGoldenFile)
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join("testdata", "cases")
	checked := 0
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || filepath.Ext(path) != ".json" {
			return err
		}
		name, _ := filepath.Rel(root, path)
		f, err := readCaseFile(name)
		if err != nil {
			return err
		}
		isolated, regular, sequence, err := caseFileCases(f)
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		compared, problems := comparedGoldens(index, isolated, regular, sequence)
		for _, problem := range problems {
			t.Errorf("%s: %s", name, problem)
		}
		for _, g := range compared {
			checked++
			subtest := g.caseID + "/" + g.subtest
			recorded := g.recordedIn(index)
			switch {
			case recorded && listed[subtest]:
				t.Errorf("%s: the golden of %s is recorded, and %s lists it; remove the line", name, subtest, requestsWithoutAGoldenFile)
			case !recorded && !listed[subtest]:
				t.Errorf("%s: %s compares with %s, which is not recorded, so it skips on every profile; record it, or list it in %s",
					name, subtest, GoldenKey(g.row, g.subCases[0]), requestsWithoutAGoldenFile)
			}
			delete(listed, subtest)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if checked == 0 {
		t.Fatalf("no golden compared under %s", root)
	}
	stale := make([]string, 0, len(listed))
	for subtest := range listed {
		stale = append(stale, subtest)
	}
	sort.Strings(stale)
	for _, subtest := range stale {
		t.Errorf("%s lists %s, which compares with no golden after the recorded setup of its case; remove the line", requestsWithoutAGoldenFile, subtest)
	}
}

// A comparedGolden is a golden a runner compares an answer of a case with.
type comparedGolden struct {
	caseID string
	// subtest is the path of the subtest that compares it, below the case.
	subtest string
	row     ParityEndpointID
	// subCases are the sub-cases of the golden's key; a golden recorded under
	// any one of them is the one compared.
	subCases []string
}

// recordedIn reports whether index holds the golden g under one of its keys.
func (g comparedGolden) recordedIn(index map[string]json.RawMessage) bool {
	return slices.ContainsFunc(g.subCases, func(subCase string) bool {
		_, ok := index[GoldenKey(g.row, subCase)]
		return ok
	})
}

// comparedGoldens returns the goldens the runners compare the answers of the
// cases of one case file with, given the recorded answers to the setup of each
// case in index, and problems with the case file that make the list
// unreliable. It follows the runners: an isolated case sends its requests after
// an accepted upload; a regular case sends its requests and runs its steps
// after an accepted declaration of its domain, where it has one, and after
// accepted uploads; a sequence case runs its steps. A step's observations
// after its status and error class are made unless the step's call was refused
// and the step stops on a refusal, and such a step ends its case. A step with
// no call is never refused. Only a recorded refusal ends anything: a setup
// answer or a step status that is not recorded is itself a compared golden
// that is missing, and counts as accepted, since the runner goes on after a
// live 2xx and compares what follows.
func comparedGoldens(index map[string]json.RawMessage, isolated []isolatedCase, regular []regularCase, sequence []sequenceCase) ([]comparedGolden, []string) {
	var compared []comparedGolden
	var problems []string
	keys := map[string]bool{}
	compare := func(caseID, subtest string, row ParityEndpointID, subCases ...string) {
		for _, subCase := range subCases {
			key := GoldenKey(row, subCase)
			if keys[key] {
				problems = append(problems, fmt.Sprintf("case %s compares two answers with the golden %s", caseID, key))
			}
			keys[key] = true
		}
		compared = append(compared, comparedGolden{caseID: caseID, subtest: subtest, row: row, subCases: subCases})
	}
	accepted := func(id ParityEndpointID, subCase string) bool {
		raw, recorded := index[GoldenKey(id, subCase)]
		if !recorded {
			return true
		}
		var outcome struct {
			Status int `json:"status"`
		}
		if err := json.Unmarshal(raw, &outcome); err != nil {
			problems = append(problems, fmt.Sprintf("the golden %s has no status: %v", GoldenKey(id, subCase), err))
			return false
		}
		return outcome.Status >= http.StatusOK && outcome.Status < http.StatusMultipleChoices
	}
	// request follows runRequest, under subtest, a request name or a path
	// that ends in one.
	request := func(caseID, subtest, subCase string, r isolatedRequest) {
		switch {
		case r.classifyBy != "":
			compare(caseID, subtest, r.outcomeRow(), subCase+"-when-the-pip-was-read", subCase+"-when-the-pip-was-skipped")
			if r.userManagementCalls {
				compare(caseID, subtest+"/user-management-calls", PSUITE_USER_MANAGEMENT_CALL, subCase)
			}
			return
		case r.pipCalls != "":
			compare(caseID, subtest+"/pip-calls", PSUITE_PIP_CALL, subCase)
		}
		if r.userManagementCalls {
			compare(caseID, subtest+"/user-management-calls", PSUITE_USER_MANAGEMENT_CALL, subCase)
		}
		compare(caseID, subtest, r.outcomeRow(), subCase)
	}
	// runSteps follows the runner's runSteps, and reports false where a step
	// ends the case.
	runSteps := func(caseID, group string, steps []regularStep) bool {
		for _, step := range steps {
			subCase := group + "/" + step.name
			refused := false
			if step.call != nil && slices.ContainsFunc(step.observe, func(o stepObservation) bool { return o.kind == "status" }) {
				refused = !accepted(step.golden, subCase)
			}
			for _, o := range step.observe {
				if refused && step.stopOnRefusal && o.kind != "status" && o.kind != "error-class" {
					break
				}
				switch o.kind {
				case "status":
					compare(caseID, step.name, step.golden, subCase)
				case "error-class":
					compare(caseID, step.name+"-error-class", PSUITE_PAP_ERROR, subCase)
				case "read":
					compare(caseID, step.name+"-read", PSUITE_PAP_READ, subCase)
				case "read-raw":
					compare(caseID, step.name+"-read-raw", PSUITE_PAP_READ_RAW, subCase)
				case "decide":
					request(caseID, o.request.name, group+"/"+o.request.name, o.request)
				case "pip-call":
					compare(caseID, step.name+"-pip-calls", PSUITE_PIP_CALL, subCase)
				default:
					problems = append(problems, fmt.Sprintf("case %s: step %s observes %q, which comparedGoldens does not follow", caseID, step.name, o.kind))
				}
			}
			if refused && step.stopOnRefusal {
				return false
			}
		}
		return true
	}
	casePIPCalls := func(caseID, group, route string) {
		if route != "" {
			compare(caseID, "the-pip-calls", PSUITE_PIP_CALL, group)
		}
	}
	for _, c := range isolated {
		group := "isolated/" + c.id
		compare(c.id, "upload", PSUITE_LOAD_SIMPLIFIED_POLICIES, group)
		if !accepted(PSUITE_LOAD_SIMPLIFIED_POLICIES, group) {
			continue
		}
		for _, r := range c.requests {
			request(c.id, r.name, group+"/"+r.name, r)
		}
		casePIPCalls(c.id, group, c.pipCalls)
	}
	for _, c := range regular {
		group := "regular/" + c.id
		if len(c.pips) > 0 || len(c.simplified) > 0 {
			compare(c.id, "declare-the-domain", PSUITE_LOAD_SIMPLIFIED_POLICIES, group+"/declare-the-domain")
			if !accepted(PSUITE_LOAD_SIMPLIFIED_POLICIES, group+"/declare-the-domain") {
				continue
			}
		}
		uploaded := true
		for i := range c.uploads {
			upload := fmt.Sprintf("upload-%d", i+1)
			compare(c.id, upload, PSUITE_LOAD_POLICY_SETS, group+"/"+upload)
			if !accepted(PSUITE_LOAD_POLICY_SETS, group+"/"+upload) {
				uploaded = false
			}
		}
		if !uploaded {
			continue
		}
		for _, r := range c.requests {
			request(c.id, r.name, group+"/"+r.name, r)
		}
		if runSteps(c.id, group, c.steps) {
			casePIPCalls(c.id, group, c.pipCalls)
		}
	}
	for _, c := range sequence {
		runSteps(c.id, "sequence/"+c.id, c.steps)
	}
	return compared, problems
}

// goldenIndex reads the goldens under root and returns each recorded answer
// under its golden key.
func goldenIndex(root string) (map[string]json.RawMessage, error) {
	index := map[string]json.RawMessage{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".json") || strings.HasSuffix(path, ".observed.json") {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		entries, err := decodeGoldenFile(filepath.ToSlash(rel), raw)
		if err != nil {
			return err
		}
		for key, answer := range entries {
			index[key] = answer
		}
		return nil
	})
	return index, err
}

// readRequestList reads a list of <case id>/<request name>, one per line;
// a blank line and a line that starts with # are skipped, and text after the
// first space of a line is a comment.
func readRequestList(path string) (map[string]bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	listed := map[string]bool{}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		listed[strings.Fields(line)[0]] = true
	}
	return listed, scanner.Err()
}

// comparedGoldens follows the runners through the recorded setup of a case: a
// step's observations after its status are made unless its call was refused
// and it stops on a refusal, a step with no call is never refused, a request
// counts what its PIPs received where it asks for that, and a golden under
// another row or another class does not stand for the request's own.
func TestComparedGoldens_FollowsTheRunnerThroughTheSetupItRecorded(t *testing.T) {
	t.Parallel()
	status := func(code int) json.RawMessage { return json.RawMessage(fmt.Sprintf(`{"status":%d}`, code)) }
	decide := func(name string) stepObservation {
		return stepObservation{kind: "decide", request: isolatedRequest{name: name}}
	}
	write := func(name string, stop bool, observe ...stepObservation) regularStep {
		return regularStep{name: name, call: &papCall{method: "PUT"}, golden: PSUITE_LOAD_POLICY_SETS, stopOnRefusal: stop,
			observe: append([]stepObservation{{kind: "status"}}, observe...)}
	}
	read := regularStep{name: "read", observe: []stepObservation{{kind: "read"}, decide("after-read")}}
	index := map[string]json.RawMessage{
		GoldenKey(PSUITE_LOAD_POLICY_SETS, "regular/c/upload-1"):                                           status(200),
		GoldenKey(PSUITE_LOAD_POLICY_SETS, "regular/c/accepted"):                                           status(200),
		GoldenKey(PSUITE_LOAD_POLICY_SETS, "regular/c/refused-goes-on"):                                    status(400),
		GoldenKey(PSUITE_LOAD_POLICY_SETS, "regular/c/refused-stops"):                                      status(400),
		GoldenKey(PSUITE_ROW_2_CHECK_RESOURCE_V1_OUTCOME, "regular/c/top"):                                 status(200),
		GoldenKey(PSUITE_ROW_6_CHECK_FILTER_V1_OUTCOME, "regular/c/after-accepted"):                        status(200),
		GoldenKey(PSUITE_ROW_2_CHECK_RESOURCE_V1_OUTCOME, "regular/c/after-read-when-the-pip-was-read"):    status(200),
		GoldenKey(PSUITE_ROW_2_CHECK_RESOURCE_V1_OUTCOME, "regular/c/classified-when-the-pip-was-skipped"): status(200),
		GoldenKey(PSUITE_ROW_2_CHECK_RESOURCE_V1_OUTCOME, "regular/c/classified-plain"):                    status(200),
		GoldenKey(PSUITE_ROW_2_CHECK_RESOURCE_V1_OUTCOME, "regular/c/counted"):                             status(200),
		GoldenKey(PSUITE_PIP_CALL, "regular/c/counted"):                                                    json.RawMessage(`{"calls":1}`),
	}
	regular := []regularCase{{
		id:       "c",
		pipCalls: "/case-pip",
		uploads:  []regularUpload{{}},
		requests: []isolatedRequest{{name: "top"}, {name: "classified", classifyBy: "/pip"}, {name: "classified-plain", classifyBy: "/pip"},
			{name: "counted", pipCalls: "/pip", userManagementCalls: true}},
		steps: []regularStep{
			write("accepted", true, decide("after-accepted")),
			read,
			write("refused-goes-on", false, decide("after-refused-goes-on")),
			write("refused-stops", true, decide("after-refused-stops")),
			write("never-run", true, decide("after-the-stop")),
		},
	}}
	compared, problems := comparedGoldens(index, nil, regular, nil)
	if len(problems) > 0 {
		t.Fatalf("comparedGoldens reports %q", problems)
	}
	got := map[string]bool{}
	for _, g := range compared {
		got[g.subtest] = g.recordedIn(index)
	}
	want := map[string]bool{
		"upload-1":                      true,
		"top":                           true,
		"classified":                    true,
		"classified-plain":              false, // access-control compares a classified request with its class goldens alone
		"counted/pip-calls":             true,
		"counted/user-management-calls": false,
		"counted":                       true,
		"accepted":                      true,
		"after-accepted":                false, // its golden is under the filter row, and the request is a check
		"read-read":                     false,
		"after-read":                    false, // a class golden stands only for a request classified by a PIP
		"refused-goes-on":               true,
		"after-refused-goes-on":         false,
		"refused-stops":                 true, // and the case ends there, before the-pip-calls of the whole case
	}
	if !maps.Equal(got, want) {
		t.Errorf("comparedGoldens compares, with whether each is recorded, %v; want %v", got, want)
	}
}

// comparedGoldens ends a case where the runner ends it: an isolated case with a
// refused upload, a regular case with a refused declaration of its domain or a
// refused upload. The setup answer that ends it is compared itself. A refused
// customize step ends nothing, and an upload or a step status that is not
// recorded is compared and counts as accepted.
func TestComparedGoldens_EndsACaseWhereItsSetupEndsIt(t *testing.T) {
	t.Parallel()
	status := func(code int) json.RawMessage { return json.RawMessage(fmt.Sprintf(`{"status":%d}`, code)) }
	decide := func(name string) stepObservation {
		return stepObservation{kind: "decide", request: isolatedRequest{name: name}}
	}
	step := func(name string, stop bool, observe ...stepObservation) regularStep {
		return regularStep{name: name, call: &papCall{method: "PUT"}, golden: PSUITE_IMPORT_CUSTOMIZATION, stopOnRefusal: stop,
			observe: append([]stepObservation{{kind: "status"}}, observe...)}
	}
	index := map[string]json.RawMessage{
		GoldenKey(PSUITE_LOAD_SIMPLIFIED_POLICIES, "isolated/i-accepted"):                  status(200),
		GoldenKey(PSUITE_LOAD_SIMPLIFIED_POLICIES, "isolated/i-refused"):                   status(400),
		GoldenKey(PSUITE_LOAD_SIMPLIFIED_POLICIES, "regular/r-declare/declare-the-domain"): status(400),
		GoldenKey(PSUITE_LOAD_POLICY_SETS, "regular/r-declare/upload-1"):                   status(200),
		GoldenKey(PSUITE_LOAD_POLICY_SETS, "regular/r-upload/upload-1"):                    status(200),
		GoldenKey(PSUITE_LOAD_POLICY_SETS, "regular/r-upload/upload-2"):                    status(400),
		GoldenKey(PSUITE_LOAD_POLICY_SETS, "regular/r-customize/upload-1"):                 status(200),
		GoldenKey(PSUITE_IMPORT_CUSTOMIZATION, "regular/r-customize/cust"):                 status(400),
		GoldenKey(PSUITE_IMPORT_CUSTOMIZATION, "sequence/s/first"):                         status(200),
	}
	isolated := []isolatedCase{
		{id: "i-accepted", requests: []isolatedRequest{{name: "i-accepted-q"}}, pipCalls: "/pip"},
		{id: "i-refused", requests: []isolatedRequest{{name: "i-refused-q"}}, pipCalls: "/pip"},
		{id: "i-unrecorded", requests: []isolatedRequest{{name: "i-unrecorded-q"}}},
	}
	regular := []regularCase{
		{id: "r-declare", pips: []any{"pip"}, uploads: []regularUpload{{}}, requests: []isolatedRequest{{name: "r-declare-q"}}},
		{id: "r-upload", uploads: []regularUpload{{}, {}}, requests: []isolatedRequest{{name: "r-upload-q"}}},
		{id: "r-customize", uploads: []regularUpload{{}}, requests: []isolatedRequest{{name: "r-customize-q"}},
			steps: []regularStep{step("cust", false, decide("after-cust"))}},
	}
	sequence := []sequenceCase{{id: "s", steps: []regularStep{
		step("first", true, decide("after-first")),
		step("unrecorded", true, decide("after-unrecorded")),
		step("unrecorded-too", true, decide("after-unrecorded-too")),
	}}}
	compared, problems := comparedGoldens(index, isolated, regular, sequence)
	if len(problems) > 0 {
		t.Fatalf("comparedGoldens reports %q", problems)
	}
	var got []string
	for _, g := range compared {
		got = append(got, g.caseID+"/"+g.subtest)
	}
	want := []string{
		"i-accepted/upload", "i-accepted/i-accepted-q", "i-accepted/the-pip-calls",
		"i-refused/upload",
		"i-unrecorded/upload", "i-unrecorded/i-unrecorded-q",
		"r-declare/declare-the-domain",
		"r-upload/upload-1", "r-upload/upload-2",
		"r-customize/upload-1", "r-customize/r-customize-q", "r-customize/cust", "r-customize/after-cust",
		"s/first", "s/after-first", "s/unrecorded", "s/after-unrecorded", "s/unrecorded-too", "s/after-unrecorded-too",
	}
	if !slices.Equal(got, want) {
		t.Errorf("comparedGoldens compares\n%q\nwant\n%q", got, want)
	}
}
