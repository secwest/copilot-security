# Cross-file invoice ownership control

The route passes both the request-controlled invoice identifier and the
authenticated customer identity into the repository wrapper. The lookup binds
both values in one query, so another customer's invoice is indistinguishable
from a missing record and is never returned.

This is the paired negative control for `javascript-cross-file-idor`.
