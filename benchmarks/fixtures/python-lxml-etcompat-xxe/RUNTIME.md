# Runtime evidence

The fixture witness was executed under Linux/WSL on Python 3.12.3 with
`lxml==6.0.2`.

The exact `ETCompatXMLParser()` default expands the fixture-local external
entity, and `fromstring(..., parser=parser)` returns the marker in the parsed
root text. The witness uses no network request, subprocess, shell, or file
outside its own fixture.
