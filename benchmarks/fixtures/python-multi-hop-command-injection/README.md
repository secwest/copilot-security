# Python multi-hop command injection

A registered Flask route passes an attacker-controlled report name through
public gateway and service relays into a separate shell-command wrapper. Both
relays use bounded multiline calls while preserving the same runtime value.
