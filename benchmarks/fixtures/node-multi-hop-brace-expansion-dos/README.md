# Vulnerable brace-expansion intermediate-array boundary

This fixture carries a request-controlled brace pattern through three wrappers
into `brace-expansion` 5.0.8. That release has `max` and `maxLength` output
bounds, but constructs padded-sequence and comma-alternative intermediate
arrays before enforcing the character limit. A small request can therefore
stall or terminate the single Node.js worker.

Run `npm install --ignore-scripts && npm test` to reproduce a bounded form of
the wasted padded-sequence work without exhausting memory.
