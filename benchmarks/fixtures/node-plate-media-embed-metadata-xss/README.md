# Reachable Plate media-embed metadata XSS

A document loader obtains serialized Plate JSON from an application API and
passes it into a configured `Plate` value. The application registers an iframe
media component through the official `MediaEmbedPlugin`; that component uses
official `useMediaState` with the video URL parser, gates on `isVideo`, and
renders `embed.url` as the iframe source. Exact `@platejs/media` 53.0.1 trusts
serialized `provider` metadata before URL protocol parsing, so a stored node can
claim Vimeo while retaining a `javascript:` render URL.

The bounded real-package witness does not open a browser, listener, or external
connection and does not execute the URL. Bun replaces only Plate's React context
hooks with deterministic values, invokes the published `useMediaState` hook
through React's server renderer, and records whether the real package retains
the inert `javascript:parent.postMessage` sentinel. Browser execution remains a
separate validation requirement.
