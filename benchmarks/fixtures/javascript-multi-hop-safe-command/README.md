# Bounded multi-hop command status service

The HTTP handler accepts one fixed status label and passes it through an
exported service relay. The process wrapper uses the trusted current runtime,
a shell-free argument vector, bounded concurrency, a timeout, and a small
output budget. The label remains inert and no network operation is performed.
