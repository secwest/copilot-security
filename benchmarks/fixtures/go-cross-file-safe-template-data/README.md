# Go cross-file safe template data

The matched control preserves the HTTP source, wrapper, renderer, request
payload, and response behavior. It parses a fixed server-owned `html/template`
and supplies the request value only as execution data. The test proves that the
template directive remains literal, the script markup is escaped, and the
server signing key is not disclosed.
