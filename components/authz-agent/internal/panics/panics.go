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

// Package panics tells recovered panics apart by the code that raised them,
// so that a panic repeated on every request is reported once per defect.
package panics

import (
	"fmt"
	"runtime"
	"runtime/debug"
	"strings"
)

// Recovered is a panic that a deferred function recovered.
type Recovered struct {
	// Value is what was passed to panic, or the runtime error.
	Value any
	// Site is the function and the file:line that raised the panic, the
	// first frame below the runtime's panic machinery, and the frame that
	// called it, so that one helper failing for two callers gives two
	// sites. It is "" when the stack shows no such frame.
	Site string
	// Stack is the stack of the goroutine that panicked, as debug.Stack
	// prints it.
	Stack []byte
}

// String returns the value, the site, and the stack, which the runtime
// prints when a *Recovered raised again is not recovered.
func (p *Recovered) String() string {
	return fmt.Sprintf("%v at %s\n%s", p.Value, p.Site, p.Stack)
}

// Catch describes value, which the deferred function that calls Catch
// directly has just recovered. A value that is a *Recovered already, raised
// again on another goroutine, is returned as it is, so its site and stack
// stay those of the goroutine that panicked first.
func Catch(value any) *Recovered {
	if r, ok := value.(*Recovered); ok {
		return r
	}
	return &Recovered{Value: value, Site: site(), Stack: debug.Stack()}
}

// site names the frame that raised the panic in progress, the first frame
// outside package runtime after runtime.gopanic, and its caller. A runtime
// error, such as a nil dereference, passes through more runtime frames on
// its way to gopanic's caller, and those are skipped too.
func site() string {
	pcs := make([]uintptr, 64)
	frames := runtime.CallersFrames(pcs[:runtime.Callers(1, pcs)])
	inPanic := false
	var raised string
	for {
		f, more := frames.Next()
		switch {
		case raised != "":
			return fmt.Sprintf("%s, called from %s (%s:%d)", raised, f.Function, f.File, f.Line)
		case f.Function == "runtime.gopanic":
			inPanic = true
		case inPanic && !strings.HasPrefix(f.Function, "runtime."):
			raised = fmt.Sprintf("%s (%s:%d)", f.Function, f.File, f.Line)
		}
		if !more {
			return raised
		}
	}
}
