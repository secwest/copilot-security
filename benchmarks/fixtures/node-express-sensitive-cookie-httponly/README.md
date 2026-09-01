# HttpOnly Express session-cookie control

This control preserves the same Express route, jsonwebtoken session value,
cookie name, Secure attribute, SameSite mode, path, and response chain as the
browser-readable fixture. It changes only `httpOnly` to `true`, excluding the
session value from browser JavaScript's `document.cookie` view.

The offline witness starts no server and uses no real token or credential. It
models only the browser visibility boundary established by the HttpOnly
attribute.
