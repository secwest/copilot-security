# Same-workflow script injection fixture

A privileged `pull_request_target` workflow inserts the attacker-controlled pull
request title directly into official `actions/github-script` source. The same
step exposes a mock release token and receives write-capable permissions.

The executable witness substitutes a harmless title payload and proves that it
becomes a second JavaScript statement rather than remaining data.
