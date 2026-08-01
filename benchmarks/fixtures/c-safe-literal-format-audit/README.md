# Literal-format audit logging

This control has the same unauthenticated username, active-session capability,
and externally visible audit sink. It fixes the format grammar to the literal
`"%s"` and passes the remote username only as the corresponding data argument.

An attacker-supplied `%s`, `%n`, positional selector, width, or conversion is
therefore emitted literally. The active capability is not a variadic argument
and cannot be selected by the untrusted username.
