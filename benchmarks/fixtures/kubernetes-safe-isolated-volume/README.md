# Isolated Kubernetes volume control

This matched control keeps the workload purpose and pinned image but opts into
a pod user namespace, disables privileged mode, and replaces the host bind
with an isolated `emptyDir`. No container receives sensitive node filesystem
authority.
