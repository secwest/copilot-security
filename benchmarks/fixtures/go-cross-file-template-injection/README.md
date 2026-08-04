# Go cross-file template injection

The HTTP handler passes a query value through one same-package wrapper as
`text/template` source. The renderer registers a server-side function, parses
the request value, and executes the resulting template. The test proves that
`{{readSigningKey}}` invokes the registered function and discloses the fixture
signing key.
