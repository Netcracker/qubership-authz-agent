# Agent instructions

Create an issue with a type (`gh issue create --type Bug|Feature|Task`), not a `bug` or `enhancement` label.

The Rego in `policies/` interprets simplified policies at run time and is maintenance-only until a translator from policies to Rego replaces it. Do not review it or report defects in it, and change it only to keep the existing tests passing.

For a fixed policy set, time and memory per request stay linear, up to a sort's log factor, in untrusted bytes from the
caller and PIPs. Reading a byte once per nesting level or per item of another array or object breaks that unless a limit
keeps it linear. Cost should stay polynomial in policy size. Input too big or too deep fails its request or load, not
the process. The Rego in `policies/` stays exempt.

Tests: Go `testing` from the standard library, with `testing/synctest` for code that waits on goroutines or timers. testify is used only in `test/integration` and `test/parity`; new tests elsewhere do not use it.
