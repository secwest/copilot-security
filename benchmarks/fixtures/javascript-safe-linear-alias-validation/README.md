# Linear alias validation fixture

The registration handler rejects non-string and overlong aliases before a
single-pass character check. It preserves the vulnerable fixture's intended
language without using a backtracking regular expression, so valid aliases
still work while the catastrophic near-match is rejected in linear time.
