# Angular HostListener missing origin check

This fixture binds an official Angular 20 component method to the global
"window:message" event. The method consumes "event.data" before checking either
the sender's exact origin or its window identity.

Run "npm run witness" to exercise the handler with fixed synthetic trusted and
attacker events. The witness makes no network request and does not start Angular.
