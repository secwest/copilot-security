# Patched dset path flow

The source, three wrappers, target, value, and official API call are identical
to the vulnerable fixture, but dset 3.1.4 converts every path segment to a
string before testing dangerous keys and blocks the nested-array bypass.
