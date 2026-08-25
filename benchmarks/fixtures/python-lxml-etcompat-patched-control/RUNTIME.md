# Runtime evidence

The control witness was executed under Linux/WSL on Python 3.12.3 with
`lxml==6.1.1`.

The source-identical `ETCompatXMLParser()` uses the patched `'internal'`
default. Parsing the external `SYSTEM` entity raises `XMLSyntaxError` and never
returns the fixture marker. The witness uses no network request, subprocess,
shell, or file outside its own fixture.
