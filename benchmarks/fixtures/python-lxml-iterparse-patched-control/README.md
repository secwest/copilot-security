# Python lxml iterparse patched control

This control preserves the vulnerable fixture's Flask route, upload stream,
relative wrapper, eager iterator consumption, byte budget, XML payload, and
fixture-local marker. Its only operative change is the exact
`lxml==6.1.1` dependency, whose default `resolve_entities='internal'` blocks
local external entity access.
