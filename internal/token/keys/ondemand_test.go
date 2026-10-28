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

package keys

import (
	"context"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

// callerKey is the key of a value the caller puts on its context.
type callerKey struct{}

// gatedReload is a reload that blocks every run until release is closed.
type gatedReload struct {
	release chan struct{}
	runs    atomic.Int32
	// canceled is whether the context of a run had ended when the run ended.
	canceled atomic.Bool
	// sawValue is whether the context of a run carried a callerKey value.
	sawValue atomic.Bool
}

func (g *gatedReload) reload(ctx context.Context) {
	g.runs.Add(1)
	if ctx.Value(callerKey{}) != nil {
		g.sawValue.Store(true)
	}
	<-g.release
	if ctx.Err() != nil {
		g.canceled.Store(true)
	}
}

// newGated returns a gatedReload and an onDemand that runs it.
func newGated() (*gatedReload, *onDemand) {
	g := &gatedReload{release: make(chan struct{})}
	return g, &onDemand{reload: g.reload, interval: time.Minute, now: time.Now}
}

// The joining caller asks while the reload that the starting caller started
// is held.
func TestOnDemand_ACallerDuringAReloadWaitsForIt(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		g, o := newGated()
		var starter, joiner atomic.Bool
		go func() { o.wait(t.Context()); starter.Store(true) }()
		synctest.Wait()
		go func() { o.wait(t.Context()); joiner.Store(true) }()
		synctest.Wait()
		if joiner.Load() {
			t.Errorf("the joining wait returned while the reload was held")
		}
		close(g.release)
		synctest.Wait()
		if !starter.Load() || !joiner.Load() {
			t.Errorf("after the reload ended: starting wait returned = %t, joining wait = %t, want both", starter.Load(), joiner.Load())
		}
		if got := g.runs.Load(); got != 1 {
			t.Errorf("reloads = %d, want 1", got)
		}
	})
}

// The caller's context ends while the reload it started is held. The reload
// keeps the values of that context.
func TestOnDemand_ACallerWhoseContextEndsStopsWaitingAndTheReloadGoesOn(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		g, o := newGated()
		ctx, cancel := context.WithCancel(context.WithValue(t.Context(), callerKey{}, "caller"))
		var returned atomic.Bool
		go func() { o.wait(ctx); returned.Store(true) }()
		synctest.Wait()
		if returned.Load() {
			t.Errorf("wait returned while the reload was held and its context lasted")
		}
		cancel()
		synctest.Wait()
		if !returned.Load() {
			t.Errorf("wait did not return after its context ended")
		}
		close(g.release)
		synctest.Wait()
		if g.canceled.Load() {
			t.Errorf("the reload's context ended with the caller's")
		}
		if !g.sawValue.Load() {
			t.Errorf("the reload's context lacks the caller's value")
		}
	})
}
