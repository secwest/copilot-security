# ASP.NET cross-file principal-bound object lookup

The endpoint accepts the same route-controlled invoice identifier as the
vulnerable fixture. The repository's single EF Core predicate binds that
identifier to the customer identifier derived from the authenticated
principal. Selecting another customer's primary key therefore returns no
entity.
