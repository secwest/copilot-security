# Safe archive link-isolation fixture

The importer rejects symbolic and hard-link entries, lexically contains every
regular member name, and delegates directory creation and file writes to
root-anchored no-follow operations. This also prevents a pre-existing link in
the extraction tree from redirecting a regular member write while preserving
ordinary nested files.
