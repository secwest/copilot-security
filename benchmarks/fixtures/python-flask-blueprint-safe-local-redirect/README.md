# Flask registered-Blueprint safe local redirect

This source-matched Flask 3.1.3 control registers the same official Blueprint
and reads the same query value. It percent-encodes that value beneath a fixed
non-root local target, preventing it from selecting another URL authority.
