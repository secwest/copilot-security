# Cross-file command status service

The unauthenticated HTTP handler forwards a caller-supplied hostname to a
separate process wrapper. The wrapper runs under the application service
account and returns command output to the caller.
