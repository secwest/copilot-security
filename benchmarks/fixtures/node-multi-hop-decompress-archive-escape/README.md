# Reachable decompression archive escape fixture

An Express request body crosses three relative-import wrappers before official `@xhmikosr/decompress` 10.2.0 extracts it to a fixed application staging directory. That release accepts archive entry paths whose resolved sibling begins with the extraction-root string, creates escaping hardlinks and symlinks, permits later writes through those links, and retains archive-supplied special mode bits.

`npm run witness` uses only the public package API and a bounded custom parser result. It attempts to write `bounded-sentinel` into a pre-created sibling directory whose name shares the extraction-root prefix, reports whether the write escaped, and removes its temporary directory. It opens no listener, reads no secret, overwrites no existing file, executes no extracted content, changes no privilege, and makes no network request.
