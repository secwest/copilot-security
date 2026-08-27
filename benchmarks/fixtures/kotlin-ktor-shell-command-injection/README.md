# Ktor shell command injection

A Ktor query parameter supplies `target`. The handler interpolates that request
value into the command-string position after `sh -c`, so the value participates
in shell grammar. The paired Kotlin test expands only a fixed inert environment
marker and performs no file, network, credential, persistence, or privilege
operation.
