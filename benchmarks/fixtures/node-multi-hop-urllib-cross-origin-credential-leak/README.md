# Vulnerable urllib redirect fixture

An inbound authorization value crosses three relative wrappers into the
standard `Authorization` header of an official urllib request. urllib 4.9.0
follows redirects by default and forwards that credential across an origin
boundary. The witness uses two loopback servers and a bounded inert token; it
does not contact an external system.
