# Axum Tokio shell command injection

An Axum `Query` extractor supplies `input.target`. The handler formats that
request value into a command string passed after `sh -c` through the official
Tokio process builder, so the value occupies shell grammar rather than one
literal argument. The paired Tokio witness expands only a fixed inert
environment marker and performs no file, network, credential, persistence, or
privilege operation.
