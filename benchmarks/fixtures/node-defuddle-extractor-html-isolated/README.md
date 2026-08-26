# Patched Defuddle site-extractor control

This source-identical negative fixture changes only the Defuddle dependency
from 0.19.0 to 0.19.1. The repaired release escapes known extractor sinks and
passes every site-extractor result through the central DOM sanitizer before
returning `DefuddleResponse.content`.

Run `npm run witness`. The bounded witness uses the same synthetic X article
and asserts that no sentinel event-handler attribute survives. It does not
execute scripts, start a server, or use the network.
