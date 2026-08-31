# Angular HostListener exact-origin control

This topology-matched control binds the same official Angular 20 global message
listener but rejects every event whose complete origin is not the configured
trusted origin before consuming "event.data".

Run "npm run witness" to exercise the guard with fixed synthetic trusted and
attacker events. The witness makes no network request and does not start Angular.
