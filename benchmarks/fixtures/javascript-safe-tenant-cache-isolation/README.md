# Tenant-isolated application-cache control

This control has the same authenticated sessions, tenant-local invoice IDs,
tenant-scoped repository, and shared in-process application cache as the
vulnerable fixture.

The cache namespace includes the tenant ID derived from the server-side
session, and every hit is checked against that authenticated tenant before the
invoice is returned. Two tenants can use the same invoice ID without sharing a
cache entry or receiving each other's sensitive invoice data.
