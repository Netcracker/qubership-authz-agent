# Agent instructions

Create an issue with a type (`gh issue create --type Bug|Feature|Task`), not a `bug` or `enhancement` label.

The Rego in `policies/` interprets simplified policies at run time and is maintenance-only until a translator from policies to Rego replaces it. Do not review it or report defects in it, and change it only to keep the existing tests passing.

Callers, PIPs, and policy authors are untrusted. For a fixed policy set, time and memory per request stay linear in the
bytes from the caller and PIPs, up to a sort's log factor. No byte is read or copied once per level of nesting or per
item of another array or object. Compiling a policy should stay polynomial, and a huge one must fail to load, not crash.
The Rego in `policies/` stays exempt from review.

Tests: Go `testing` from the standard library, with `testing/synctest` for code that waits on goroutines or timers. testify is used only in `test/integration` and `test/parity`; new tests elsewhere do not use it.
