# Python multi-hop command injection

A registered Flask route passes an attacker-controlled report name through a
public service relay into a separate shell-command wrapper. The relay uses a
bounded multiline call while preserving the same runtime value.
