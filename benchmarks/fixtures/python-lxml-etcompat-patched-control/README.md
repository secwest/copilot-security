# Python lxml ET-compatible parser patched control

This control is source-identical to the affected Flask fixture: the same upload
crosses the same wrapper into `lxml.etree.fromstring` with the same
`ETCompatXMLParser()` construction. Its only operative difference is the exact
`lxml==6.1.1` dependency, whose patched default is
`resolve_entities='internal'` and does not permit local external-entity access.

The witness constructs a `file:` URI only for `examples/entity-marker.txt`. It
does not access the network, launch a shell, or read any non-fixture file.
