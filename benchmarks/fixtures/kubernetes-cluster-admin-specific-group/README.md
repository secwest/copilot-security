# Specific Kubernetes administrator group control

This source-identical control binds `cluster-admin` to one explicitly managed
administrator group instead of an intrinsic Kubernetes catch-all principal.
The scanner must not treat every deliberate cluster administrator binding as a
broad-subject vulnerability.
