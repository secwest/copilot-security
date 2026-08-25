# Python lxml ET-compatible parser XXE benchmark

This Flask fixture passes a request-controlled XML upload through a relative
wrapper into `lxml.etree.fromstring` with an explicitly constructed
`ETCompatXMLParser`. The exact `lxml==6.0.2` dependency retains that parser's
affected default `resolve_entities=True`, allowing a local `SYSTEM` entity to
disclose a file readable by the service process.

The witness constructs a `file:` URI only for `examples/entity-marker.txt`. It
does not access the network, launch a shell, or read any non-fixture file.
