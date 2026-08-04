# Spring Data object-authorization control fixture

The controller passes the route identifier and the real Spring Security `Authentication` object to a typed service. The service binds both the requested invoice ID and `authentication.getName()` into the same derived Spring Data query.

`InvoiceAuthorizationWitnessTest` proves a cross-customer selection is rejected while the caller's own invoice remains available.
