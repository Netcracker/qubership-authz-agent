# Parity stand — authz-agent runtime config

## `trusted-providers.json`

One provider, the parity realm, mounted at `/etc/authz/trusted-providers.json`
by `../docker-compose.authz-agent.yml`.

### Why `allowMissingAud: true`

It is load-bearing, not decoration. Under authz-agent-ADR-0049's legacy-ingress
relay contract this realm mints two kinds of token that have to verify through
the *same* provider entry:

- M2M admission tokens carrying `aud: netcracker`;
- end-user subject tokens relayed via `Incoming-Token`, which the
  `parity-end-user` password-grant client deliberately mints with **no** `aud`
  at all — it has no audience mapper (see `clientId=parity-end-user` in
  `../idp-seed/parity-realm.json`).

`io.jwt.decode_verify` will not accept both shapes through one constraint set:
with an `aud` constraint the audience-less token fails, and without one the
`aud`-carrying token fails. `allowMissingAud` opts this entry into the
audience-less verification branch for tokens that have no `aud` claim, while
tokens carrying a *wrong* `aud` are still rejected.

The flag only means anything alongside `audiences`. An entry with no `audiences`
does not check `aud` at all, so it needs no opt-in (authz-agent-ADR-0075 §5).

This explanation used to live in a `_comment` field inside the JSON itself.
It cannot any more: since authz-agent-ADR-0075 the trusted-providers file is
parsed strictly and an unknown field is a startup error.
