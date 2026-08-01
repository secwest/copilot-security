# Shell-free cross-file command status service

The HTTP handler accepts one fixed status-check label and forwards it to a
separate process wrapper. The wrapper selects the trusted current runtime and
supplies the label only as an inert structured argument with the shell disabled.
It also bounds concurrent children, execution time, and captured output. The
fixture performs no attacker-selected network operation.
