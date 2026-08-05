# Go constructor-injected interface-field object deletion

The handler injects one of multiple repository implementations into a service
constructor. The selected implementation receives an attacker-controlled object
identifier and deletes without principal scope. The deterministic witness proves
that the interface dispatch reaches the selected primary repository.
