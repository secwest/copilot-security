# LogTape syslog structured-data injection fixture

This fixture configures the official LogTape syslog sink on an exact loopback
UDP port with structured data explicitly enabled. An exported request handler
places one request-body value in the logger's record-properties argument. The
witness sends an inert newline-delimited marker, captures one datagram, reports
only byte indexes and booleans, and disposes the logger and socket.

The paired control uses identical application and witness bytes. Only the
`@logtape/syslog` dependency changes from affected 2.1.4 to repaired 2.1.5.
