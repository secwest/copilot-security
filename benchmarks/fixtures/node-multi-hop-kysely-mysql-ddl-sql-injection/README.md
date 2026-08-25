# Kysely MySQL DDL literal-escape witness

The request field crosses three relative-module wrappers into the value
position of `CreateIndexBuilder.where()`. Kysely 0.28.13 compiles the bounded
advisory input with insufficient MySQL backslash escaping. The witness only
compiles SQL: it opens no database or socket and changes no external state.
