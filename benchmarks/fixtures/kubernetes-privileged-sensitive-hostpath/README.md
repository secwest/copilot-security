# Privileged sensitive hostPath

This fixture deploys one pinned Linux container in privileged mode and mounts
the node root through the same exact Kubernetes volume name with read-write
access. The benchmark validates the joined workload, container, volume, and
mount path rather than treating either `privileged` or `hostPath` alone as a
complete host-compromise path.
