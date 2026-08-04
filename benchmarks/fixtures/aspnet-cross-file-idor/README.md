# ASP.NET cross-file object authorization control

The authenticated endpoint accepts an invoice identifier from the route and
passes it through a typed repository boundary to `DbSet.FindAsync`. The lookup
uses only the attacker-selected primary key. `[Authorize]` establishes endpoint
access but does not authorize the current principal for the returned invoice.

The paired safe fixture preserves the same route, repository, entity, and EF
Core topology while constraining the lookup by the authenticated customer.
