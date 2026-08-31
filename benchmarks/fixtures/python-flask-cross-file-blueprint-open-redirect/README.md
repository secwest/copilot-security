# Flask cross-file Blueprint open redirect

This Flask 3.1.3 application-factory fixture imports a Blueprint from a sibling
module, mounts it with a literal URL prefix, and returns the official Flask
application. The route places only `/` before a query value, allowing an input
that begins with `/` to select another origin. The witness inspects `Location`
without following the redirect or performing external I/O.
