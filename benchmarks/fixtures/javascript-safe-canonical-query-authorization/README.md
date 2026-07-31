# Canonical query-authorization control

The gateway strictly decodes the query once, rejects duplicate decoded names
and unknown fields, authorizes the resulting immutable parameter object, and
passes that same object downstream. The backend does not reparse raw input and
also enforces the administrative delete permission. Encoded spellings of a
duplicate key cannot create a second interpretation.
