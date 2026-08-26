# Repaired Echo encoded-separator control

This source-identical control changes only Echo from 4.15.2 to 4.15.3. The
direct `/admin/marker.txt` request still reaches the middleware and is denied.
The encoded `/admin%2Fmarker.txt` request is rejected with 404 before the static
handler can turn the encoded separator into a filesystem boundary.

The shared real-package witness uses only `httptest` and a test-owned temporary
directory; it opens no listener and contacts no external service.
