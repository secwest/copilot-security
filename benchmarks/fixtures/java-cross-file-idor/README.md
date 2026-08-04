# Spring Data object-authorization exploit fixture

An authenticated customer selects an invoice identifier in the route. The controller passes that identifier through a typed service to Spring Data `findById`, which retrieves another customer's invoice without an object-level authorization decision.

`InvoiceAuthorizationWitnessTest` seeds two customers and proves the authenticated first customer can retrieve the second customer's invoice.
