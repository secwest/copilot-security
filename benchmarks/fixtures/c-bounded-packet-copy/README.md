# Bounded packet copy

This control uses the same unauthenticated login-packet format and fixed
session structure. Before copying, the parser proves that the packet contains
the declared bytes and that the username plus its terminator fits the
destination field.

The adjacent authorization byte therefore remains outside the writable range.
