# Python multi-hop SQL injection

A registered Flask route passes an attacker-controlled email address through
public gateway and service relays into a database wrapper that inserts it into
SQLite query grammar before execution.
