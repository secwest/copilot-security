# Python multi-hop SQL injection

A registered Flask route passes an attacker-controlled email address through a
public service relay into a database wrapper that inserts it into SQLite query
grammar before execution.
