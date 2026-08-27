# AsyncSSH SCP download boundary pair

This fixture and its control intentionally contain byte-identical application,
documentation, and witness source. Only the exact production dependency pin
changes.

`src/downloader.py` uses the documented remote-source tuple form of
`asyncssh.scp()` and a local `Path` destination. The safe witness starts a
loopback-only SSH server which sends a fixed inert marker under the filename
`../escaped-marker.txt`. The requested directory and escaped marker both remain
inside one disposable temporary root.

The witness never uses a home directory, startup file, SSH configuration,
authorization file, executable location, credential, or persistent path.
AsyncSSH 2.23.1 rejects the filename. Even after that repair, SCP can still
overwrite server-selected names inside the requested destination, so SFTP is
the preferred protocol.
