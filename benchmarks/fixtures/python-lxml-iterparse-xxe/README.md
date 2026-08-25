# Python lxml iterparse XXE benchmark

The Flask route passes a bounded request-controlled XML stream through one
relative wrapper into eagerly consumed `lxml.etree.iterparse`. The exact
`lxml==6.0.2` dependency retains the affected default
`resolve_entities=True`, allowing a local `SYSTEM` entity to disclose a file
before parsing returns.

The witness reads only `examples/entity-marker.txt` from this fixture. It does
not access the network, invoke a shell, or read any non-fixture file.
