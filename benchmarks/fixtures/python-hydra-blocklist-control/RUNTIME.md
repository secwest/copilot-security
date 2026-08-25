# Runtime contract

The bounded witness is accepted on Ubuntu with Python 3.12.3 and
`hydra-core==1.3.4`. It asks `builtins.eval` to evaluate only the fixed
arithmetic expression `6 * 7`. It does not launch a shell, read or write a file,
open a network connection, mutate process state, or access a credential.
