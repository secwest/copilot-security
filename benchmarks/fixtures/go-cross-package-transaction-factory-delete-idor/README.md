# Go cross-package transaction-factory object deletion

The DELETE route passes a path-selected invoice into a mutation wrapper that
obtains its transaction through two imported, aliased factory packages. The
leaf factory calls the real `database/sql` `BeginTx`, and the wrapper commits
the staged mutation. The offline driver proves that an attacker can make a
victim invoice deletion durable without principal scope.
