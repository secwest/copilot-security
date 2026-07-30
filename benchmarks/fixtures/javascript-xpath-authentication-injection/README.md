# XPath authentication-injection fixture

This service constrains the interpolated username to an account-name grammar
but interpolates a request-controlled password verifier into an XPath predicate
used to select the account installed in the caller's application session. An
attacker can close the password literal and add a role predicate, causing the
XML directory to select the administrator node without a valid password
verifier. `src/directory.js` contains the bounded XPath subset,
administrator/viewer XML-account data model, boolean precedence, node selection,
and variable semantics used by this fixture.
