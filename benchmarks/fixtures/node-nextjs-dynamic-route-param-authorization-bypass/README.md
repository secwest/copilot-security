# Next.js dynamic-route parameter authorization bypass

This fixture pins `next` 15.5.15. Its middleware denies the visible protected
path `/documents/secret`, while the matching Pages Router SSR page uses
`params.slug` for server-side document lookup. In affected deployment routing
flows an external `?nxtPslug=secret` value can become the page parameter after
middleware has authorized a public pathname.

The witness builds and starts the real standalone package on a disposable
loopback port. It records important counterevidence: an ordinary standalone
request resolves the visible `public` segment first and does not reproduce the
bypass. It then exercises the real route-module handoff used when a trusted
deployment proxy invokes the dynamic route template. The affected package
normalizes the external `nxtPslug=secret` value even when the request is marked
as wrapped by the normal Next server. The source-identical 15.5.16 control
filters it. The witness reads no existing file, contacts no external service,
and performs no application write.
