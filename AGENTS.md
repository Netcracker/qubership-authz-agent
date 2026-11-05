# Agent instructions

Create an issue with a type (`gh issue create --type Bug|Feature|Task`), not a `bug` or `enhancement` label.

The Rego in `policies/` interprets simplified policies at run time and is maintenance-only until a translator from policies to Rego replaces it. Do not review it or report defects in it, and change it only to keep the existing tests passing.

Everything a caller or a PIP sends is untrusted. Time and memory per request stay linear, apart from the log factor of a
sort, in the bytes received from the caller and from PIPs, whatever their shape. No byte is read or copied once per
level of nesting or once per item of another array or object. Policies are trusted; their size counts as a constant. The
Rego in `policies/` stays exempt from review.

Tests: Go `testing` from the standard library, with `testing/synctest` for code that waits on goroutines or timers. testify is used only in `test/integration` and `test/parity`; new tests elsewhere do not use it.
