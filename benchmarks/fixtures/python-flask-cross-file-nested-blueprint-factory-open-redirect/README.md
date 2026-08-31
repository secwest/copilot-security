# Flask cross-file nested Blueprint factory open redirect

This Flask 3.1.3 application spreads one reachable route across three modules.
An application factory imports a parent Blueprint, the parent imports and
registers a child Blueprint, and the child places only `/` before a query value.
Registration-time prefixes override constructor defaults, so the effective route
is `/root/child/continue`. The witness inspects `Location` without following the
redirect or performing external I/O.
