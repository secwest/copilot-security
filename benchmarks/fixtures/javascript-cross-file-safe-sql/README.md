# Parameter-bound cross-file user lookup service

The unauthenticated HTTP handler forwards a caller-supplied email address to a
separate database wrapper. The wrapper keeps that value outside SQL syntax by
using the driver's positional parameter binding.
