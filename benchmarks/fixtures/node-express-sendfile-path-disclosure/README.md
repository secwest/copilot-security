# Express `sendFile` absolute-path disclosure

The literal `GET /download` route passes `request.query.path` directly to
Express `response.sendFile` without a `root` option. An attacker can therefore
select an absolute path readable by the service account instead of being
confined to an application-owned download directory.

The witness uses only disposable inert marker files and an in-memory HTTP
request/response pair. It starts no listener and performs no network access.
