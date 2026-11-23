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

// waitIn runs o.wait(ctx) in a new goroutine and returns a channel that gets
// its error once it returns.
func waitIn(ctx context.Context, o *onDemand) <-chan error {
	done := make(chan error, 1)
	go func() {
		_, err := o.wait(ctx)
		done <- err
	}()
	return done
}

// The joining caller asks while the reload that the starting caller started
// is held.
func TestOnDemand_ACallerDuringAReloadWaitsForIt(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		g, o := newGated()
		starter := waitIn(t.Context(), o)
		synctest.Wait()
		joiner := waitIn(t.Context(), o)
		synctest.Wait()
		select {
		case err := <-joiner:
			t.Errorf("the joining wait returned %v while the reload was held", err)
		default:
		}
		close(g.release)
		synctest.Wait()
		for _, w := range []struct {
			name string
			done <-chan error
		}{{"starting", starter}, {"joining", joiner}} {
			select {
			case err := <-w.done:
				if err != nil {
					t.Errorf("the %s wait returned %v after the reload ended, want nil", w.name, err)
				}
			default:
				t.Errorf("the %s wait did not return after the reload ended", w.name)
			}
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
		done := waitIn(ctx, o)
		synctest.Wait()
		select {
		case err := <-done:
			t.Errorf("wait returned %v while the reload was held and its context lasted", err)
		default:
		}
		cancel()
		synctest.Wait()
		select {
		case err := <-done:
			if !errors.Is(err, context.Canceled) {
				t.Errorf("wait() error = %v after its context ended, want %v", err, context.Canceled)
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
