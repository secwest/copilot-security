# Python multi-hop safe command execution

The registered Flask route crosses the same public service relay, but the
wrapper invokes one fixed executable with an argument vector, disables shell
parsing, checks the exit status, and bounds execution time.
