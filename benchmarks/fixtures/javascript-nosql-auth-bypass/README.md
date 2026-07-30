# Document-query authentication bypass

The public session endpoint accepts JSON values and inserts the parsed values
directly into an account document query. An attacking client can submit MongoDB
operator objects such as `{ "$ne": null }` for both credential fields.

The query then selects an account without knowing either credential, and the
route copies that account's identity and role into the attacker's session.
