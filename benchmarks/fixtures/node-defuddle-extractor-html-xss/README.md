# Defuddle site-extractor HTML XSS

This executable positive fixture models a clipping service that accepts remote
HTML, passes it through the official `defuddle/node` entry point in an exported
relative wrapper, and serves `DefuddleResponse.content` as HTML. Defuddle
0.19.0 lets an X article header-image attribute escape the extractor's template
string and become an executable output attribute.

Run `npm run witness`. The bounded witness parses a synthetic X article with
the exact installed package and checks only whether a sentinel `onerror`
attribute survives. It does not execute the attribute, start a server, or use
the network.
