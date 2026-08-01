# Cross-file user lookup service

The unauthenticated HTTP handler forwards a caller-supplied email address to a
separate database wrapper. The wrapper queries the production user database
and returns matching records to the caller.
