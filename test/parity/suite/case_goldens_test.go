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

// requestsWithoutAGoldenFile lists the requests of the case files that are
// known to have no golden, one <case id>/<request name> per line.
const requestsWithoutAGoldenFile = "testdata/requests-without-a-golden.txt"

// Each request of a case file that the runners send has a recorded golden
// under the key they compare its answer with, or is listed in
// requests-without-a-golden.txt. A request with no golden skips as not
// recorded on every profile, so the run that misses it still passes; this
// test makes such a gap a failure until the golden is recorded or the request
// is listed. A listed request that has a golden fails as well, so the list
// shrinks as goldens are recorded. Which requests are sent is read from the
// recorded setup, in the order of the runners (sentRequests).
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
		sent, problems := sentRequests(index, isolated, regular, sequence)
		for _, problem := range problems {
			t.Errorf("%s: %s", name, problem)
		}
		for _, r := range sent {
			checked++
			request := r.caseID + "/" + r.request.name
			recorded := hasGolden(index, r)
			switch {
			case recorded && listed[request]:
				t.Errorf("%s: request %s has a golden and is listed in %s; remove the line", name, request, requestsWithoutAGoldenFile)
			case !recorded && !listed[request]:
				t.Errorf("%s: request %s has no golden under %s, so it skips on every profile; record it, or list it in %s with the reason",
					name, request, GoldenKey(r.request.outcomeRow(), r.subCase), requestsWithoutAGoldenFile)
			}
			delete(listed, request)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if checked == 0 {
		t.Fatalf("no request under %s", root)
	}
	stale := make([]string, 0, len(listed))
	for request := range listed {
		stale = append(stale, request)
	}
	sort.Strings(stale)
	for _, request := range stale {
		t.Errorf("%s lists %s, which is no request the runners send after the recorded setup of its case; remove the line", requestsWithoutAGoldenFile, request)
	}
}

// A sentRequest is a request of a case that a runner sends, with the golden
// key it compares the answer with, less the row's directory.
type sentRequest struct {
	caseID  string
	subCase string
	request isolatedRequest
}

// sentRequests returns the requests the runners send for the cases of one
// case file, given the recorded answers to the setup of each case in index, and
// problems with the case file that make the list unreliable. It follows the
// runners: an isolated case sends its requests after an accepted upload; a
// regular case sends its requests and runs its steps after an accepted
// declaration of its domain, where it has one, and after accepted uploads; a
// sequence case runs its steps. A step's decide requests are sent unless the
// step's call was refused and the step stops on a refusal, and such a step
// ends its case. A step with no call is never refused. Only a recorded
// refusal ends anything: a setup answer or a step status that is not recorded
// counts as accepted, since the runner goes on after a live 2xx and sends
// what follows.
func sentRequests(index map[string]json.RawMessage, isolated []isolatedCase, regular []regularCase, sequence []sequenceCase) ([]sentRequest, []string) {
	var sent []sentRequest
	var problems []string
	names := map[string]bool{}
	send := func(caseID, group string, r isolatedRequest) {
		if names[caseID+"/"+r.name] {
			problems = append(problems, fmt.Sprintf("case %s sends two requests named %s, whose goldens share one key", caseID, r.name))
		}
		names[caseID+"/"+r.name] = true
		sent = append(sent, sentRequest{caseID: caseID, subCase: group + "/" + r.name, request: r})
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
	runSteps := func(caseID, group string, steps []regularStep) {
		for _, step := range steps {
			refused := false
			if step.call != nil && slices.ContainsFunc(step.observe, func(o stepObservation) bool { return o.kind == "status" }) {
				refused = !accepted(step.golden, group+"/"+step.name)
			}
			for _, o := range step.observe {
				if refused && step.stopOnRefusal && o.kind != "status" && o.kind != "error-class" {
					break
				}
				if o.kind == "decide" {
					send(caseID, group, o.request)
				}
			}
			if refused && step.stopOnRefusal {
				return
			}
		}
	}
	for _, c := range isolated {
		if ok := accepted(PSUITE_LOAD_SIMPLIFIED_POLICIES, "isolated/"+c.id); !ok {
			continue
		}
		for _, r := range c.requests {
			send(c.id, "isolated/"+c.id, r)
		}
	}
	for _, c := range regular {
		group := "regular/" + c.id
		if len(c.pips) > 0 || len(c.simplified) > 0 {
			if ok := accepted(PSUITE_LOAD_SIMPLIFIED_POLICIES, group+"/declare-the-domain"); !ok {
				continue
			}
		}
		uploaded := true
		for i := range c.uploads {
			if ok := accepted(PSUITE_LOAD_POLICY_SETS, fmt.Sprintf("%s/upload-%d", group, i+1)); !ok {
				uploaded = false
			}
		}
		if !uploaded {
			continue
		}
		for _, r := range c.requests {
			send(c.id, group, r)
		}
		runSteps(c.id, group, c.steps)
	}
	for _, c := range sequence {
		runSteps(c.id, "sequence/"+c.id, c.steps)
	}
	return sent, problems
}

// hasGolden reports whether index holds the golden r is compared with on
// access-control: the one under its own key, or for a request classified by a
// PIP's call log, the one under either order class, which is all access-control
// compares such a request with.
func hasGolden(index map[string]json.RawMessage, r sentRequest) bool {
	subCases := []string{r.subCase}
	if r.request.classifyBy != "" {
		subCases = []string{r.subCase + "-when-the-pip-was-read", r.subCase + "-when-the-pip-was-skipped"}
	}
	for _, subCase := range subCases {
		if _, ok := index[GoldenKey(r.request.outcomeRow(), subCase)]; ok {
			return true
		}
	}
	return false
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

// sentRequests follows the runners through the recorded setup of a case: a
// step's decide requests are sent unless its call was refused and it stops on
// a refusal, a step with no call is never refused, and a golden under another
// row or another class does not stand for the request's own.
func TestSentRequests_FollowsTheRunnerThroughTheSetupItRecorded(t *testing.T) {
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
	}
	regular := []regularCase{{
		id:       "c",
		uploads:  []regularUpload{{}},
		requests: []isolatedRequest{{name: "top"}, {name: "classified", classifyBy: "/pip"}, {name: "classified-plain", classifyBy: "/pip"}},
		steps: []regularStep{
			write("accepted", true, decide("after-accepted")),
			read,
			write("refused-goes-on", false, decide("after-refused-goes-on")),
			write("refused-stops", true, decide("after-refused-stops")),
			write("never-run", true, decide("after-the-stop")),
		},
	}}
	sent, problems := sentRequests(index, nil, regular, nil)
	if len(problems) > 0 {
		t.Fatalf("sentRequests reports %q", problems)
	}
	got := map[string]bool{}
	for _, r := range sent {
		got[r.request.name] = hasGolden(index, r)
	}
	want := map[string]bool{
		"top":                   true,
		"classified":            true,
		"classified-plain":      false, // access-control compares a classified request with its class goldens alone
		"after-accepted":        false, // its golden is under the filter row, and the request is a check
		"after-read":            false, // a class golden stands only for a request classified by a PIP
		"after-refused-goes-on": false,
	}
	if !maps.Equal(got, want) {
		t.Errorf("sentRequests sends, with whether a golden stands for each, %v; want %v", got, want)
	}
}

// sentRequests ends a case where the runner ends it: an isolated case with a
// refused upload, a regular case with a refused declaration of its domain or a
// refused upload. A refused customize step ends nothing, and an upload or a
// step status that is not recorded counts as accepted.
func TestSentRequests_EndsACaseWhereItsSetupEndsIt(t *testing.T) {
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
		{id: "i-accepted", requests: []isolatedRequest{{name: "i-accepted-q"}}},
		{id: "i-refused", requests: []isolatedRequest{{name: "i-refused-q"}}},
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
	sent, problems := sentRequests(index, isolated, regular, sequence)
	if len(problems) > 0 {
		t.Fatalf("sentRequests reports %q", problems)
	}
	var got []string
	for _, r := range sent {
		got = append(got, r.caseID+"/"+r.request.name)
	}
	want := []string{"i-accepted/i-accepted-q", "i-unrecorded/i-unrecorded-q", "r-customize/r-customize-q", "r-customize/after-cust",
		"s/after-first", "s/after-unrecorded", "s/after-unrecorded-too"}
	if !slices.Equal(got, want) {
		t.Errorf("sentRequests sends %q, want %q", got, want)
	}
}
