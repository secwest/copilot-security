# Primitive-only document-query login

This control uses the same public session route and account query. Before query
construction, it requires both credential fields to be primitive strings and
applies bounded allowlists. Parsed JSON objects, arrays, MongoDB operators, and
other non-string values are rejected before the database call.
