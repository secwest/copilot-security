# Login session rotation

The login bootstrap ignores supplied session identifiers and creates a fresh
unpredictable anonymous session. After credential verification, authentication
atomically deletes the pre-authentication session, creates a new unpredictable
identifier bound to the account, and sets that identifier in the browser.
Neither an attacker-created session nor the victim's old anonymous identifier
can be used after login.
