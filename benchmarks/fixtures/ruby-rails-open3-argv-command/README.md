# Rails Open3 fixed executable and argument vector

This topology-matched control retains the Rails request source, Open3 process
execution, output capture, and response. It changes only the command boundary:
the executable and format are fixed and the request value is a separate
argument, so shell metacharacters remain data.

`witness.rb` passes the same harmless semicolon payload and confirms that the
environment marker is not expanded.
