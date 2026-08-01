# Asynchronous audit use-after-free

An administrator session starts a deferred audit export and then disconnects.
The fixed-size session pool releases that object, but the pending operation
retains its raw pointer. An unprivileged client deterministically reuses the
same slot before the export completes, so the completion callback follows the
stale pointer and sends the administrator-only report to the attacker.

The pool models object reuse explicitly so the executable witness is stable
across compilers and operating systems instead of relying on allocator luck or
undefined-behavior diagnostics.
