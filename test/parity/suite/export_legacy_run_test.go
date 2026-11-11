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
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"maps"
	"net/http"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"authz-agent/test/parity/suite/model"
)

// TestExportFedLegacyAgent is part A of the export-fed profile: it feeds the
// agent the v3 exports legacy access-control held, as the raw reads of the
// sequence cases recorded them, and compares the agent's decisions with the
// legacy goldens recorded at the same point (legacyExportCases). Each point's
// export is mounted on the export source with a canary set beside it in each
// tenant its decisions run in (legacyCanaries). The point's setup subtests
// fail, with setupBrokenPrefix, when the agent does not load the export or one
// of its tenants: the pull fails, or a canary is denied. The decisions that
// depend on it are then skipped and counted apart (setUpLegacyPoint), because
// the agent holds another configuration. A golden fails when the agent's answer differs from it, unless the kind of its
// class (set-type for set-type:DEFAULT) is listed in
// acceptedExportDivergences and the answer allows nothing the golden denies,
// or the entry covers such an answer too (AllowsMore). It runs only under
// PARITY_PROFILE=authz-agent-export (make parity-export-legacy);
// PARITY_EXPORT_RUN selects the cases whose <file>/<case id> it matches.
func TestExportFedLegacyAgent(t *testing.T) {
	cfg := LoadConfig()
	if !isExportFedProfile(cfg.Profile) {
		t.Skipf("PARITY_PROFILE=%s; the export-fed agent runs under %s", cfg.Profile, exportFedProfile)
	}
	ecfg, err := LoadExportFedConfig()
	if err != nil {
		t.Fatal(err)
	}
	cases, err := allLegacyExportCases(NewGoldenComparator(cfg).goldenRoot)
	if err != nil {
		t.Fatal(err)
	}
	s := &ParitySuite{cfg: cfg, tokens: NewTokenFactory(cfg), comparator: NewGoldenComparator(cfg),
		pipMock: NewPipController(cfg.PipMockControlURL), eaMock: NewPipController(cfg.EAMockControlURL),
		umMock: NewPipController(cfg.UMMockControlURL)}
	source := &stubExportSource{stub: NewPipController(ecfg.SourceControlURL), timeout: ecfg.PullTimeout, poll: 200 * time.Millisecond}
	ctx := context.Background()
	var all []legacyResult
	uncompared := map[string]string{}
	mounted := 0
	stand := cfg.TenantID
	for _, lc := range cases {
		name := lc.file + "/" + lc.id
		if ecfg.Run != nil && !ecfg.Run.MatchString(name) {
			continue
		}
		maps.Copy(uncompared, lc.uncompared)
		if len(lc.points) == 0 {
			continue
		}
		t.Run(name, func(t *testing.T) {
			defer func() { s.cfg.TenantID = stand }()
			caseBroken := runSetup(t, func(t *testing.T) error {
				s.SetT(t)
				for _, c := range []*PipController{s.pipMock, s.eaMock, s.umMock} {
					if err := c.ResetPinnedRoutes(ctx); err != nil {
						return fmt.Errorf("reset the stubs: %w", err)
					}
				}
				s.pinRoutes(lc.pins)
				s.pinUserManagement(lc.userManagement)
				return nil
			})
			for _, p := range lc.points {
				mounted++
				canaries := legacyCanaries(p, mounted, valueOr(lc.tenant, stand), stand)
				t.Run(p.step, func(t *testing.T) {
					setup := legacyPointSetup{point: caseBroken}
					if caseBroken == "" {
						setup = setUpLegacyPoint(t, p, canaries, stand, legacyPointLoader{
							mount: func(t *testing.T, ps, pips json.RawMessage) error {
								s.SetT(t)
								return source.Mount(ctx, ps, pips)
							},
							allowed: func(t *testing.T, c legacyCanary) bool {
								s.SetT(t)
								s.cfg.TenantID = c.tenant
								return s.legacyCanaryAllowed(c.rt)
							},
						})
					}
					for _, d := range p.decisions {
						t.Run(d.path, func(t *testing.T) {
							if broken := setup.brokenFor(d); broken != "" {
								all = append(all, brokenLegacyResult(lc, p, d, broken))
								skipIfBroken(t, broken)
							}
							s.SetT(t)
							s.cfg.TenantID = d.tenant
							res := s.judgeLegacyDecision(lc, p, d)
							all = append(all, res)
							switch {
							case res.WrongAllow && res.Verdict == verdictDiffers:
								t.Errorf("WRONG ALLOW %s (class %s): %s", res.Path, res.Class, res.Detail)
							case res.Verdict == verdictDiffers:
								t.Errorf("%s (class %s): %s", res.Path, res.Class, res.Detail)
							case res.Verdict == verdictAccepted:
								t.Logf("ACCEPTED DIVERGENCE %s: %s", res.Path, res.Detail)
							case res.Verdict == verdictSkipped:
								t.Skipf("SKIPPED %s: %s", res.Path, res.Detail)
							}
						})
					}
				})
			}
		})
	}
	s.SetT(t)
	t.Log("\n" + legacyExportReport(all, uncompared))
	if len(all) == 0 {
		t.Error("no golden compared: PARITY_EXPORT_RUN matched no case with a legacy export")
	}
}

// allLegacyExportCases reads every case file under testdata/cases and returns
// the cases of legacyExportCases, those whose every decision is uncompared
// included.
func allLegacyExportCases(goldenRoot string) ([]legacyExportCase, error) {
	names, err := caseFileNames()
	if err != nil {
		return nil, err
	}
	var out []legacyExportCase
	for _, name := range names {
		f, err := readCaseFile(name)
		if err != nil {
			return nil, err
		}
		cases, err := legacyExportCases(name, f, goldenRoot)
		if err != nil {
			return nil, err
		}
		out = append(out, cases...)
	}
	return out, nil
}

// caseFileNames returns the names of the case files under testdata/cases,
// relative to it and sorted, as readCaseFile takes them.
func caseFileNames() ([]string, error) {
	root := filepath.Join("testdata", "cases")
	var names []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || filepath.Ext(path) != ".json" {
			return err
		}
		name, _ := filepath.Rel(root, path)
		names = append(names, filepath.ToSlash(name))
		return nil
	})
	slices.Sort(names)
	return names, err
}

// legacyPointLoader mounts the export of a point and checks one of its
// canaries; the run drives the stand through it.
type legacyPointLoader struct {
	mount   func(t *testing.T, ps, pips json.RawMessage) error
	allowed func(t *testing.T, c legacyCanary) bool
}

// legacyPointSetup is the outcome of the setup of a point: the report of a
// setup that broke for every decision of the point, or else the report per
// tenant whose canary was denied.
type legacyPointSetup struct {
	point   string
	tenants map[string]string
	stand   string
}

// brokenFor returns the report of the broken setup that the decision d waits
// on, or "" when d can be compared.
func (b legacyPointSetup) brokenFor(d legacyDecision) string {
	if b.point != "" {
		return b.point
	}
	return b.tenants[valueOr(d.tenant, b.stand)]
}

// setUpLegacyPoint mounts the export of p with canaries through l and checks
// them, the first, which is in the tenant of the case, in the subtest "setup"
// and each other in a subtest "setup <tenant>". A denied canary means the
// agent holds another configuration of its tenant, and the decisions in that
// tenant are broken. When the mount fails, or every canary is denied, the
// agent holds none of the export, and every decision of p is broken, those in
// a tenant without a canary included.
func setUpLegacyPoint(t *testing.T, p legacyExportPoint, canaries []legacyCanary, stand string, l legacyPointLoader) legacyPointSetup {
	t.Helper()
	b := legacyPointSetup{tenants: map[string]string{}, stand: stand}
	mounted := false
	first := runSetup(t, func(t *testing.T) error {
		ps, pips, err := legacyExportDocuments(p, canaries)
		if err != nil {
			return err
		}
		if err := l.mount(t, ps, pips); err != nil {
			return fmt.Errorf("mount the export of step %s: %w", p.step, err)
		}
		mounted = true
		return deniedCanary(t, p, canaries[0], l)
	})
	if !mounted {
		b.point = first
		return b
	}
	denied := 0
	if first != "" {
		b.tenants[canaries[0].tenant] = first
		denied++
	}
	for _, c := range canaries[1:] {
		report := runNamedSetup(t, "setup "+c.tenant, func(t *testing.T) error { return deniedCanary(t, p, c, l) })
		if report != "" {
			b.tenants[c.tenant] = report
			denied++
		}
	}
	if denied == len(canaries) {
		b.point = setupBroken(fmt.Errorf("the agent did not load the export of step %s: the canary of each of its %d tenants is denied",
			p.step, len(canaries)))
	}
	return b
}

// deniedCanary checks the canary c of point p through l and returns an error
// when the agent denies it.
func deniedCanary(t *testing.T, p legacyExportPoint, c legacyCanary, l legacyPointLoader) error {
	if l.allowed(t, c) {
		return nil
	}
	return fmt.Errorf("the agent did not load tenant %s of the export of step %s: the canary set %s is denied "+
		"there, so the agent holds another configuration of that tenant", c.tenant, p.step, c.rt)
}

// legacyCanaryAllowed checks the canary type for parity-reader and reports
// whether the agent allows it, that is, whether it loaded the export mounted
// with that canary.
func (s *ParitySuite) legacyCanaryAllowed(canary string) bool {
	_, outcome := s.sendRequest(canary, isolatedRequest{name: "canary", operation: "READ"}, s.requestTokens(isolatedRequest{}))
	got, ok := outcome.(*model.CheckResourceOutcome)
	return ok && got.Status == http.StatusOK && got.Decision
}

// judgeLegacyDecision sends the decision d at point p of case lc and compares
// the answer with its golden, or with the recorded variants of its order
// class.
func (s *ParitySuite) judgeLegacyDecision(lc legacyExportCase, p legacyExportPoint, d legacyDecision) legacyResult {
	req := d.request
	res := legacyResult{exportResult: exportResult{Test: lc.file + "/" + lc.id, Path: d.path, Status: "legacy",
		Families: featureFamilies(p.features), Class: legacyClass(p)}, Features: p.features}
	s.pinRoutes(req.pins)
	s.pinUserManagement(req.userManagement)
	time.Sleep(req.pause)
	id, actual := s.sendRequest(lc.resourceType, req, s.requestTokens(req))
	paths := legacyGoldenPaths(s.comparator.goldenRoot, id, d.path)
	if len(paths) == 0 {
		res.Verdict, res.Detail = verdictSkipped, "no golden is recorded"
		return res
	}
	wants := make([]any, len(paths))
	var diffs []string
	for i, path := range paths {
		want, err := readGoldenTarget(s.comparator.goldenRoot, id, path)
		if err != nil {
			res.Verdict, res.Detail = verdictDiffers, err.Error()
			return res
		}
		wants[i] = want
		_, sub, _ := goldenRow(path)
		diff := sameOutcome(id, sub, want, actual)
		if diff == "" {
			res.Verdict = verdictMatch
			return res
		}
		diffs = append(diffs, diff)
	}
	res.Verdict, res.Detail = verdictDiffers, strings.Join(diffs, "\n")
	res.WrongAllow = grantsMore(actual, wants)
	if accepted, ok := acceptedLegacyDifference(res.Class, res.WrongAllow); ok {
		res.Verdict = verdictAccepted
		res.Detail = "class " + res.Class + ", decided in " + accepted.Decision + ": " + accepted.Reason
	}
	return res
}
