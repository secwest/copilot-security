# Flask cross-file nested Blueprint factory local-redirect control

This source-matched Flask 3.1.3 control preserves the same three-module
application factory, parent/child Blueprint chain, and registration-time prefix
overrides. It percent-encodes the hostile query value beneath a fixed non-root
local destination. The witness inspects `Location` without following the
redirect or performing external I/O.
