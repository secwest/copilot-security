# Safe HTTP response-header fixture

The download endpoint rejects CR/LF and other control bytes before a filename
can reach the raw response serializer, emits a quoted ASCII fallback plus an
RFC 5987 encoded filename, and preserves ordinary and international filenames.
The same gateway and internal-file behavior are retained as a negative control.
