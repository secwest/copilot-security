# Vue Router client-side request forgery

This fixture reads a browser-controlled Vue Router query value and appends it
to the pathname passed to `fetch`. A `../` segment is resolved by the browser
before the request is sent, so the value can select a different same-origin API
endpoint than the application intended.

Run `npm run witness` to check URL resolution without starting an application
or making a network request. The witness uses only fixed synthetic values.
