# Repaired Plate media-embed metadata control

This fixture is source-identical to the affected application but pins
`@platejs/media` 53.1.4. That release recomputes embed metadata from the render
URL, so the serialized Vimeo claim cannot carry a `javascript:` URL past
`parseMediaUrl` and the iframe path receives no embed.

The shared bounded witness invokes the real published hook without opening a
browser or executing the URL and asserts that the unsafe serialized value is
not retained.
