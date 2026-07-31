# Login session fixation

The login bootstrap accepts an existing anonymous session identifier from the
request and installs it in the victim browser. Successful authentication
promotes that same session record without rotating its identifier. An attacker
who created the anonymous session can therefore fix it into a victim browser,
wait for the victim to sign in, and reuse the known identifier as the victim.
Secure, HTTP-only cookie flags do not invalidate the attacker-known identifier.
