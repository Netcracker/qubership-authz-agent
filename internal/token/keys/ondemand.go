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
// while a reload runs waits for that reload instead of starting another,
// and a reload starts at most once per interval. It is safe for concurrent
// use.
type onDemand struct {
	reload   func(context.Context)
	interval time.Duration
	now      func() time.Time

	mu sync.Mutex
	// running is closed when the reload in progress ends, and is nil while
	// none runs.
	running chan struct{}
	// started is when the last reload started, zero before the first.
	started time.Time
}

// wait starts a reload unless one runs already or the last one started less
// than interval ago, and then waits until the running reload ends or ctx
// ends. With no reload running and none allowed to start, it returns at
// once. The reload runs with the values of ctx but not with its deadline or
// cancellation, so it goes on for the other callers after ctx ends.
func (o *onDemand) wait(ctx context.Context) {
	o.mu.Lock()
	running := o.running
	if running == nil {
		now := o.now()
		if !o.started.IsZero() && now.Sub(o.started) < o.interval {
			o.mu.Unlock()
			return
		}
		o.started = now
		running = make(chan struct{})
		o.running = running
		go o.run(context.WithoutCancel(ctx), running)
	}
	o.mu.Unlock()
	select {
	case <-running:
	case <-ctx.Done():
	}
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
