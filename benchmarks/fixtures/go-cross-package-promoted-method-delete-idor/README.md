# Cross-package promoted-method object-authorization exploit

The handler constructs a service that embeds a repository through two local concrete struct levels. Go promotes `Store.DeleteInvoice` onto `Service`, so the apparently direct service call reaches an unscoped `DELETE` selected only by the request path identifier. The executable test proves that an attacker-chosen victim identifier changes database state.
