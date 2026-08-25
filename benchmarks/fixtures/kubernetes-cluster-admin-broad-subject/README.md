# Broad Kubernetes cluster-admin binding

This fixture binds the built-in `cluster-admin` ClusterRole to the documented
cluster-wide `system:serviceaccounts` group. Kubernetes warns that this gives
every application using a service account full control of the cluster. The
benchmark requires the scanner to preserve the exact principal, binding, role
reference, scope, and source lines before the model evaluates deployment and
credential reachability.
