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
	"errors"
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
	current := &atomic.Pointer[loadResult]{}
	current.Store(&loadResult{})
	return g, &onDemand{load: g.reload, current: current, interval: time.Minute, loads: newWindowLimit(maxLoadsPerMinute)}
}

// The joining caller asks while the reload that the starting caller started
// is held.
func TestOnDemand_ACallerDuringAReloadWaitsForIt(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		g, o := newGated()
		starter, joiner := make(chan error, 1), make(chan error, 1)
		go func() {
			_, err := o.wait(t.Context())
			starter <- err
		}()
		synctest.Wait()
		go func() {
			_, err := o.wait(t.Context())
			joiner <- err
		}()
		synctest.Wait()
		if len(joiner) != 0 {
			t.Errorf("the joining wait returned while the reload was held")
		}
		close(g.release)
		synctest.Wait()
		if len(starter) == 0 || len(joiner) == 0 {
			t.Fatalf("after the reload ended: starting wait returned = %t, joining wait = %t, want both", len(starter) != 0, len(joiner) != 0)
		}
		if startErr, joinErr := <-starter, <-joiner; startErr != nil || joinErr != nil {
			t.Errorf("after the reload ended: starting wait error = %v, joining wait error = %v, want none", startErr, joinErr)
		}
		if got := g.runs.Load(); got != 1 {
			t.Errorf("reloads = %d, want 1", got)
		}
	})
}

// Both the load and the context have ended before the wait looks at them, and a
// select picks at random among ready cases, so the wait runs a hundred times.
func TestOnDemand_AWaitWhoseContextEndedWithTheLoadKeepsTheResultOfTheLoad(t *testing.T) {
	ended := make(chan struct{})
	close(ended)
	o := &onDemand{running: ended}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	for call := range 100 {
		if _, err := o.wait(ctx); err != nil {
			t.Fatalf("wait() call %d with the load and the context ended: error = %v, want nil", call+1, err)
		}
	}
}

// The caller's context ends while the reload it started is held. The reload
// keeps the values of that context.
func TestOnDemand_ACallerWhoseContextEndsStopsWaitingAndTheReloadGoesOn(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		g, o := newGated()
		ctx, cancel := context.WithCancel(context.WithValue(t.Context(), callerKey{}, "caller"))
		returned := make(chan error, 1)
		go func() {
			_, err := o.wait(ctx)
			returned <- err
		}()
		synctest.Wait()
		if len(returned) != 0 {
			t.Errorf("wait returned while the reload was held and its context lasted")
		}
		cancel()
		synctest.Wait()
		select {
		case err := <-returned:
			if !errors.Is(err, context.Canceled) {
				t.Errorf("wait() after its context ended: error = %v, want %v", err, context.Canceled)
			}
		default:
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
