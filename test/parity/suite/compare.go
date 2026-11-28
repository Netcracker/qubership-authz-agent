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
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"slices"
	"strings"

	"authz-agent/test/parity/suite/model"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

// GoldenComparator reads the goldens and diffs an answer against them. A single
// comparator instance is shared across all replay tests; it stores the
// on-disk golden root (defaults to test/parity/suite/testdata/golden under
// the module root). The goldens are a frozen capture of the legacy
// access-control service behaviour — they cannot be regenerated from this
// repository (the legacy service source is not included).
type GoldenComparator struct {
	goldenRoot string
}

// NewGoldenComparator builds a comparator bound to the given config. The
// golden root is resolved relative to the current working directory — tests
// run from the module root, so testdata/golden points at the correct tree.
func NewGoldenComparator(_ Config) *GoldenComparator {
	return &GoldenComparator{
		goldenRoot: "testdata/golden",
	}
}

// Recorded returns the golden of row id under subCase, and reports whether one
// is recorded.
func (gc *GoldenComparator) Recorded(id ParityEndpointID, subCase string) (json.RawMessage, bool, error) {
	return goldensAt(gc.goldenRoot).Lookup(GoldenKey(id, subCase))
}

// Compare asserts parity between the actual (freshly-decoded) response and
// the committed golden at <row,subCase>.
//
// The actual parameter must be a typed Go pointer matching the row's
// NewGoldenTarget factory; passing the wrong type is a test-authoring
// bug and panics fast at compare time.
func (gc *GoldenComparator) Compare(id ParityEndpointID, subCase string, actual any) error {
	return gc.compare(id, subCase, actual, true)
}

// CompareAny compares actual with the golden of row id under each of subCases
// that is recorded, and returns nil as soon as one matches. It returns an error
// that wraps ErrGoldenNotRecorded when none of them is recorded, and otherwise
// an error that carries the mismatch with each recorded one, whose
// .observed.json entries then hold actual. Nothing is written when one
// matches.
func (gc *GoldenComparator) CompareAny(id ParityEndpointID, subCases []string, actual any) error {
	var mismatches []error
	var mismatched []string
	for _, subCase := range subCases {
		err := gc.compare(id, subCase, actual, false)
		switch {
		case err == nil:
			return nil
		case errors.Is(err, ErrGoldenNotRecorded):
			continue
		}
		mismatches = append(mismatches, err)
		var mismatch *GoldenMismatchError
		if errors.As(err, &mismatch) {
			mismatched = append(mismatched, subCase)
		}
	}
	if len(mismatches) == 0 {
		return fmt.Errorf("%w: none of %s under %s", ErrGoldenNotRecorded, strings.Join(subCases, ", "), Meta(id).GoldenDir)
	}
	for _, subCase := range mismatched {
		gc.writeObservedSidecar(GoldenKey(id, subCase), actual)
	}
	return fmt.Errorf("the answer matches none of the %d recorded goldens: %w", len(mismatches), errors.Join(mismatches...))
}

// compare is Compare; record says whether a mismatch writes actual to the
// .observed.json file.
func (gc *GoldenComparator) compare(id ParityEndpointID, subCase string, actual any, record bool) error {
	key := GoldenKey(id, subCase)
	goldens := goldensAt(gc.goldenRoot)
	where := goldens.Where(key)

	raw, ok, err := goldens.Lookup(key)
	if err != nil {
		return fmt.Errorf("read golden %s: %w", where, err)
	}
	if !ok {
		return fmt.Errorf("%w: %s", ErrGoldenNotRecorded, where)
	}

	expected := NewGoldenTarget(id)
	if err := json.Unmarshal(raw, expected); err != nil {
		return fmt.Errorf("unmarshal golden %s: %w", where, err)
	}

	if reflect.TypeOf(actual) != reflect.TypeOf(expected) {
		panic(fmt.Sprintf("paritysuite: comparator type mismatch for row %d: actual=%T expected=%T", int(id), actual, expected))
	}

	received := actual
	expected = normalizeComparable(id, subCase, expected)
	actual = normalizeComparable(id, subCase, actual)

	opts := compareOptionsFor(id)
	if diff := cmp.Diff(expected, actual, opts...); diff != "" {
		if record {
			gc.writeObservedSidecar(key, received)
		}
		if accepted, ok := acceptedDivergenceFor(id, subCase); ok {
			return gc.compareAgainstAccepted(id, subCase, where, actual, accepted, opts)
		}
		return &GoldenMismatchError{GoldenPath: where, Diff: diff}
	}
	return nil
}

// compareAgainstAccepted handles a case registered in acceptedDivergences. The
// response is compared against the recorded divergent answer with the same
// options used for the golden, so the case keeps asserting something exact: it
// passes only if the agent still answers the way the decision says it should.
func (gc *GoldenComparator) compareAgainstAccepted(
	id ParityEndpointID,
	subCase string,
	goldenPath string,
	actual any,
	accepted AcceptedDivergence,
	opts []cmp.Option,
) error {
	acceptedPath := acceptedDivergencePath(GoldenKey(id, subCase))

	raw, err := os.ReadFile(acceptedPath)
	if err != nil {
		return fmt.Errorf(
			"case %s/%s is registered as an accepted divergence but its recorded answer is missing at %s: %w",
			Meta(id).GoldenDir, subCase, acceptedPath, err)
	}

	recorded := NewGoldenTarget(id)
	if err := json.Unmarshal(raw, recorded); err != nil {
		return fmt.Errorf("unmarshal accepted divergence %s: %w", acceptedPath, err)
	}
	recorded = normalizeComparable(id, subCase, recorded)

	if diff := cmp.Diff(recorded, actual, opts...); diff != "" {
		return &AcceptedDivergenceDriftError{
			GoldenPath:   goldenPath,
			AcceptedPath: acceptedPath,
			Reason:       accepted.Reason,
			Diff:         diff,
		}
	}

	// Passing quietly would let the suite read as fully equivalent to legacy when
	// it is not. Say so on every run.
	fmt.Printf("ACCEPTED DIVERGENCE %s/%s: differs from %s as decided in %s — %s\n",
		Meta(id).GoldenDir, subCase, goldenPath, accepted.Decision, accepted.Reason)
	return nil
}

// writeObservedSidecar records actual under key in the .observed.json file
// beside the golden file that holds key. A failure to write it is ignored: the
// mismatch error carries the diff either way.
func (gc *GoldenComparator) writeObservedSidecar(key string, actual any) {
	encoded, err := json.Marshal(actual)
	if err != nil {
		return
	}
	_ = observedAt(gc.goldenRoot).Put(map[string]json.RawMessage{key: encoded})
}

// compareOptionsFor returns the cmp.Option set for a given row. The comparison
// leaves out three fields, and nothing else: the Obligations member of the
// legacy check and filter answers of a row that sets IgnoreObligations, the
// Body of a pap-error-v1 golden, and, through [normalizeComparable], the
// Message of every outcome that records the body of a refusal. A field joins
// them only where two conforming servers may answer it differently, with the
// reason beside the option.
func compareOptionsFor(id ParityEndpointID) []cmp.Option {
	meta := Meta(id)
	opts := []cmp.Option{}
	if meta.SortSlices {
		opts = append(opts, cmpopts.SortSlices(func(a, b string) bool { return a < b }))
	}
	if id == PSUITE_PAP_ERROR {
		// The error body is recorded for the spec repository, which compares the
		// class of its message rather than its text: the text changes between
		// builds of access-control and differs in a replacement PAP.
		opts = append(opts, cmpopts.IgnoreFields(model.PapErrorOutcome{}, "Body"))
	}
	if meta.IgnoreObligations {
		// These rows send obligations=false, so the member is not under test
		// here; the v2 outcome rows record it.
		opts = append(opts,
			cmpopts.IgnoreFields(model.CheckResourceResponse{}, "Obligations"),
			cmpopts.IgnoreFields(model.CheckResourcesResponse{}, "Obligations"),
			cmpopts.IgnoreFields(model.FilterResponse{}, "Obligations"),
		)
	}
	return opts
}

// normalizeComparable rewrites a decoded golden or answer into the form the
// comparison sees. Every outcome that records the body of a refusal goes
// through withoutMessage, so a golden with the body and one without compare
// alike; every v2 outcome goes through withSortedObligations; and every
// check/filter row goes through normalizeFilterOrder, which states which lists
// of a filter compare without regard to their order.
func normalizeComparable(id ParityEndpointID, subCase string, v any) any {
	v = withoutMessage(v)
	v = withSortedObligations(v)
	switch id {
	case PSUITE_ROW_6_CHECK_FILTER_V1, PSUITE_ROW_6_CHECK_FILTER_V1_OUTCOME, PSUITE_ROW_10_CHECK_FILTER_V2,
		PSUITE_ROW_10_CHECK_FILTER_V2_OUTCOME:
		return normalizeFilterOrder(v)
	}
	return v
}

// withSortedObligations returns a copy of v with every list of strings in its
// obligations member sorted when v is a v2 outcome, and v itself otherwise.
// The fields of an obligation name a set of resource fields, and a merge of
// the obligations of several roles need not list them in one order from run
// to run.
func withSortedObligations(v any) any {
	switch typed := v.(type) {
	case *model.CheckResourceV2Outcome:
		clone := *typed
		clone.Obligations.Value = sortedStringLists(clone.Obligations.Value)
		return &clone
	case *model.CheckResourceBulkOperationsV2Outcome:
		clone := *typed
		clone.Obligations.Value = sortedStringLists(clone.Obligations.Value)
		return &clone
	case *model.FilterV2Outcome:
		clone := *typed
		clone.Obligations.Value = sortedStringLists(clone.Obligations.Value)
		return &clone
	}
	return v
}

// sortedStringLists returns a copy of v, a decoded JSON value, in which every
// array whose elements are all strings is sorted.
func sortedStringLists(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for key, value := range x {
			out[key] = sortedStringLists(value)
		}
		return out
	case []any:
		out := make([]any, len(x))
		strs := true
		for i, e := range x {
			out[i] = sortedStringLists(e)
			_, ok := e.(string)
			strs = strs && ok
		}
		if strs {
			slices.SortFunc(out, func(a, b any) int { return strings.Compare(a.(string), b.(string)) })
		}
		return out
	}
	return v
}

// withoutMessage returns a copy of v with its Message cleared when v is an
// outcome that records the body of a refusal, and v itself otherwise. The body
// is the stand's wording, which a replacement need not match; the status beside
// it is what the golden asserts.
func withoutMessage(v any) any {
	switch typed := v.(type) {
	case *model.PolicyLoadOutcome:
		clone := *typed
		clone.Message = nil
		return &clone
	case *model.CheckResourceOutcome:
		clone := *typed
		clone.Message = nil
		return &clone
	case *model.FilterOutcome:
		clone := *typed
		clone.Message = nil
		return &clone
	case *model.CheckResourceBulkOutcome:
		clone := *typed
		clone.Message = nil
		return &clone
	case *model.CheckResourceBulkOperationsOutcome:
		clone := *typed
		clone.Message = nil
		return &clone
	case *model.CheckResourceV2Outcome:
		clone := *typed
		clone.Message = nil
		return &clone
	case *model.CheckResourceBulkOperationsV2Outcome:
		clone := *typed
		clone.Message = nil
		return &clone
	case *model.FilterV2Outcome:
		clone := *typed
		clone.Message = nil
		return &clone
	}
	return v
}

// ErrGoldenNotRecorded is returned by [GoldenComparator.Compare] when no answer
// is recorded under the golden key of the case. A case whose golden is expected to exist treats it
// as a failure; a case written ahead of its golden capture skips on it (see
// requirePendingGolden).
var ErrGoldenNotRecorded = errors.New("golden not recorded")

// GoldenMismatchError carries the diff text so the testify assertion layer
// can surface it via s.T().Errorf without re-invoking cmp.Diff.
type GoldenMismatchError struct {
	GoldenPath string
	Diff       string
}

func (e *GoldenMismatchError) Error() string {
	return fmt.Sprintf("golden mismatch at %s:\n%s", e.GoldenPath, e.Diff)
}
