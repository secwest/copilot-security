# Flask built-in `str` open redirect

This fixture passes a Flask query value through the live Python built-in
`str(object)` conversion before redirecting it. Because the request value is
already a string, the conversion preserves the attacker-selected absolute URL.
The witness uses Flask's in-process test client, disables redirect following,
and performs no external request.
