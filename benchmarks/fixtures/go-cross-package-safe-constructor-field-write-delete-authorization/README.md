# Go authorized constructor-field-write object deletion

This control preserves both implementations, pointer alias, post-construction
field writes, nested pointer layer, scalar state, interface dispatch, SQL
execution, and HTTP response. It adds only the authenticated principal
predicate, preventing cross-account deletion through the selected repository.
