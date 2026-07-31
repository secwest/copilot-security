# Web cache deception fixture

The edge treats any successful path ending in a static-looking extension as a
shared-cache object. The origin independently removes the final static-looking
path segment before routing, so `/account/profile.css` reaches the
cookie-authenticated `/account` handler. Although that handler marks its
response `private, no-store`, the edge stores it under a cache key that excludes
the session cookie. A later unauthenticated request for the same attacker-chosen
path receives the victim's control-plane API key.
