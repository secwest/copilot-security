# ASP.NET multi-hop safe-path fixture

The request value crosses the same controller, facade, and storage topology as
the vulnerable fixture. The storage boundary rejects rooted input, resolves
both the trusted root and candidate to full paths, and uses
`Path.GetRelativePath` to reject parent or independently rooted results before
the file operation. This avoids both `Path.Combine` absolute-reset behavior and
the sibling-prefix error caused by a bare string-prefix check.

The content root is server-owned and not writable by the requester. If a real
deployment permits an attacker to create links or reparse points inside that
root, lexical containment alone is insufficient and the open operation must
also enforce a link-safe filesystem boundary.
