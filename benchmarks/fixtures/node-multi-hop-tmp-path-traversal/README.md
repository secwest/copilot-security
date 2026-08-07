# tmp path-traversal fixture

An Express query-string prefix crosses three relative-import boundaries into
`tmp.fileSync` 0.2.5. A `../` prefix is normalized outside the configured
temporary root before the application writes protected export data through the
returned descriptor. The random suffix limits exact filename selection but does
not restore the intended directory boundary.

The matched control pins `tmp` 0.2.6, which rejects relative prefix components
before generating or creating the file.
