# LDAP group authorization fixture

This service trusts a federated session's `directorySubject` and interpolates it
directly into an LDAP group-membership filter. An authenticated attacker can
close the `member` assertion, add presence assertions, and make the directory
return the administrators group without being one of its members. The caller
then installs an administrator application session.
