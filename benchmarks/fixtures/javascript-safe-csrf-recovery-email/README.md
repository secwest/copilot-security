# CSRF-protected recovery-email change

The account application uses the same `SameSite=None` session cookie and
recovery-email workflow as the vulnerable control. At session creation it
generates a 256-bit CSRF token. The state-changing route requires the exact
session-bound token in the submitted form and compares fixed-size decoded bytes
in constant time before loading or modifying the account.
