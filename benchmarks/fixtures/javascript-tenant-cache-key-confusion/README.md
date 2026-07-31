# Cross-tenant application-cache fixture

This fixture models an authenticated invoice API backed by a repository that
correctly scopes every cold lookup to the tenant from the server-side session.
Invoice identifiers are tenant-local, so different tenants may legitimately
use the same identifier.

The application cache is global but keyed only by invoice ID. After one tenant
warms the cache, another authenticated tenant requesting the same local ID
receives the first tenant's invoice and download token without reaching the
tenant-scoped repository lookup.
