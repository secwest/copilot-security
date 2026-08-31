# Flask `request.values` open redirect

This fixture reads an attacker-selected redirect destination from Flask's
official combined query/form `request.values` collection. The witness uses a
GET query field, disables redirect following, inspects only the emitted
Location, and performs no external request.
