# Spring multi-hop path traversal

`DocumentController` forwards a request parameter through `DocumentService`
and `DocumentStore`. `Path.resolve` accepts parent traversal and replaces the
configured content root when the later path is absolute. `Files.readString`
therefore reads outside the intended document directory.
