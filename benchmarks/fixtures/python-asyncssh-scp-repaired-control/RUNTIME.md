# Runtime evidence

The paired witness is tested with Python 3.12.3. It starts an in-process
AsyncSSH server on a random loopback port and confines every file operation to
an automatically removed temporary directory.

The affected environment installs `asyncssh==2.23.0`; the repaired control
installs `asyncssh==2.23.1`. The witness records the version it actually imports
and fails closed when it observes any other topology or outcome.
