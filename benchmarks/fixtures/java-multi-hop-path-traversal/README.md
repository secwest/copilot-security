# Spring multi-hop path traversal

`DocumentController` forwards a request parameter through `DocumentFacade`,
`DocumentService`, and `DocumentStore`: three uniquely typed,
constructor-injected service boundaries. `Path.resolve` accepts parent
traversal and replaces the configured content root when the later path is
absolute. `Files.readString` therefore reads outside the intended document
directory.
