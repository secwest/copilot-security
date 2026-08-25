# Patched Kysely MySQL DDL literal witness

This control is source-identical to the affected fixture and changes only
Kysely to 0.28.14. The repaired MySQL compiler escapes backslashes before
quotes, preserving the bounded input inside the generated string literal.
