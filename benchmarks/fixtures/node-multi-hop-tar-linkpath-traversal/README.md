# Vulnerable node-tar linkpath traversal

An upload path crosses three application wrappers before `tar.x` 7.5.10 extracts it. The affected release can materialize a `Link` or `SymbolicLink` entry outside the extraction root through the reviewed linkpath-normalization bypasses. Later reads or writes through the extracted entry can therefore reach the external file.

`witness.mjs` reproduces the final drive-relative normalization disagreement without installing the vulnerable package.
