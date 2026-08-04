# Go cross-file prepared-statement object deletion

The DELETE route passes a path-selected invoice ID through one wrapper, prepares
a fixed `database/sql` DELETE statement, and executes it without binding the
selected object to the authenticated principal. The offline driver witness
proves that an attacker can delete the victim-owned invoice.
