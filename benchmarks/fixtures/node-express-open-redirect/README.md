# Express root-prefix open redirect

This fixture registers a literal Express 5 route and passes a query value to
`res.redirect`. Prepending only `/` does not confine the destination: a value
that begins with `/` produces a scheme-relative Location whose authority is
attacker-selected.

Run `npm run witness` to check URL resolution without starting a server or
making a network request. The witness uses only fixed synthetic values.
