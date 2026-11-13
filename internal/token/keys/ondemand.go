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
	"slices"
	"sync"
	"time"
)

// onDemand runs the on-demand loads of one source for the callers that ask for
// one. A caller that asks while a load runs waits for that load instead of
// starting another. A load starts at most once per interval, and only when
// loads admits it. It is safe for concurrent use.
type onDemand struct {
	load     func(context.Context)
	interval time.Duration
	// loads is the limit this onDemand shares with the others of a [Set].
	loads *windowLimit
	// refused runs when loads refuses a load that interval allows.
	refused func(now time.Time)

	mu sync.Mutex
	// running is closed when the load in progress ends, and is nil while
	// none runs.
	running chan struct{}
	// started is when the last load started, zero before the first.
	started time.Time
}

// wait starts a load unless one runs already, the last one started less than
// interval ago, or loads refuses another, and then waits until the running load
// ends or ctx ends. With no load running and none allowed to start, it returns
// at once. The load runs with the values of ctx but not with its deadline or
// cancellation, so it goes on for the other callers after ctx ends.
func (o *onDemand) wait(ctx context.Context) {
	o.mu.Lock()
	running := o.running
	if running == nil {
		now := time.Now()
		if !o.spaced(now) {
			o.mu.Unlock()
			return
		}
		if !o.loads.take(now) {
			o.mu.Unlock()
			o.refused(now)
			return
		}
		running = o.start(ctx, now)
	}
	o.mu.Unlock()
	select {
	case <-running:
	case <-ctx.Done():
	}
}

// begin starts a load that the caller has taken from loads.
func (o *onDemand) begin(ctx context.Context, now time.Time) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.start(ctx, now)
}

// start runs load in a new goroutine and returns the channel closed when it
// ends. The caller holds mu.
func (o *onDemand) start(ctx context.Context, now time.Time) chan struct{} {
	o.started = now
	running := make(chan struct{})
	o.running = running
	go o.run(context.WithoutCancel(ctx), running)
	return running
}

// spaced reports whether interval has passed since the last start. The
// caller holds mu.
func (o *onDemand) spaced(now time.Time) bool {
	return o.started.IsZero() || now.Sub(o.started) >= o.interval
}

// idle reports whether no load runs and another may start at now as far as
// interval goes. When it reports false, due is the earliest time at which it
// can report true: the end of interval, or a second from now while a load
// runs past it.
func (o *onDemand) idle(now time.Time) (idle bool, due time.Time) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.running == nil && o.spaced(now) {
		return true, time.Time{}
	}
	due = o.started.Add(o.interval)
	if !due.After(now) {
		due = now.Add(time.Second)
	}
	return false, due
}

// run calls load and then closes done, the running channel of this load.
func (o *onDemand) run(ctx context.Context, done chan struct{}) {
	defer func() {
		o.mu.Lock()
		o.running = nil
		o.mu.Unlock()
		close(done)
	}()
	o.load(ctx)
}

// windowLimit admits at most max events per [loadWindow], counted over the
// last loadWindow rather than per calendar minute. It is safe for concurrent
// use.
type windowLimit struct {
	max int

	mu sync.Mutex
	// starts holds the times of the events admitted in the last loadWindow,
	// oldest first.
	starts []time.Time
}

func newWindowLimit(limit int) *windowLimit {
	return &windowLimit{max: limit, starts: make([]time.Time, 0, limit)}
}

// take reports whether an event at now is admitted, and counts it if so.
func (l *windowLimit) take(now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.starts = slices.DeleteFunc(l.starts, func(t time.Time) bool { return now.Sub(t) >= loadWindow })
	if len(l.starts) >= l.max {
		return false
	}
	l.starts = append(l.starts, now)
	return true
}

// refund uncounts an event that take admitted at now and that did not happen
// after all.
func (l *windowLimit) refund(now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if i := slices.Index(l.starts, now); i >= 0 {
		l.starts = slices.Delete(l.starts, i, i+1)
	}
}
