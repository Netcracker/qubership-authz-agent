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
	"sync"
	"time"
)

// onDemand runs reload for the callers that ask for one. A caller that asks
// while a reload runs waits for that reload instead of starting another. A
// reload starts at most once per interval, and only when loads admits it. It
// is safe for concurrent use.
type onDemand struct {
	reload   func(context.Context)
	interval time.Duration
	now      func() time.Time
	// loads is the ceiling this onDemand shares with the others of a [Set].
	loads *ceiling
	// refused runs when loads refuses a reload that interval allows.
	refused func(now time.Time)

	mu sync.Mutex
	// running is closed when the reload in progress ends, and is nil while
	// none runs.
	running chan struct{}
	// started is when the last reload started, zero before the first.
	started time.Time
}

// wait starts a reload unless one runs already, the last one started less
// than interval ago, or loads refuses another, and then waits until the
// running reload ends or ctx ends. With no reload running and none allowed to
// start, it returns at once. The reload runs with the values of ctx but not
// with its deadline or cancellation, so it goes on for the other callers
// after ctx ends. It reports false when loads refused the reload or ctx ended
// first, because this caller was owed a load and did not get its result. With
// a reload not due yet it reports true: the result of the last load stands.
func (o *onDemand) wait(ctx context.Context) bool {
	o.mu.Lock()
	running := o.running
	if running == nil {
		now := o.now()
		if !o.spaced(now) {
			o.mu.Unlock()
			return true
		}
		if !o.loads.take(now) {
			o.mu.Unlock()
			o.refused(now)
			return false
		}
		running = o.start(ctx, now)
	}
	o.mu.Unlock()
	select {
	case <-running:
		return true
	case <-ctx.Done():
		return false
	}
}

// begin starts a reload that the caller has taken from loads.
func (o *onDemand) begin(ctx context.Context, now time.Time) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.start(ctx, now)
}

// start runs reload in a new goroutine and returns the channel closed when it
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

// idle reports whether no reload runs and another may start at now as far as
// interval goes.
func (o *onDemand) idle(now time.Time) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.running == nil && o.spaced(now)
}

// run calls reload and then closes done, the running channel of this
// reload.
func (o *onDemand) run(ctx context.Context, done chan struct{}) {
	defer func() {
		o.mu.Lock()
		o.running = nil
		o.mu.Unlock()
		close(done)
	}()
	o.reload(ctx)
}

// ceiling admits at most len(starts) events per [loadWindow], counted over
// the last loadWindow rather than per calendar minute. It is safe for
// concurrent use.
type ceiling struct {
	mu sync.Mutex
	// starts is a ring of the times of the last admitted events; next indexes
	// the oldest.
	starts []time.Time
	next   int
}

func newCeiling(limit int) *ceiling {
	return &ceiling{starts: make([]time.Time, limit)}
}

// take reports whether an event at now is admitted, and counts it if so.
func (c *ceiling) take(now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if oldest := c.starts[c.next]; !oldest.IsZero() && now.Sub(oldest) < loadWindow {
		return false
	}
	c.starts[c.next] = now
	c.next = (c.next + 1) % len(c.starts)
	return true
}
