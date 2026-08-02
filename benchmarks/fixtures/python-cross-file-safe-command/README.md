# Python cross-file safe command execution

The Flask route crosses the same relative-import boundary, but the wrapper
invokes one fixed executable with an argument vector, disables shell parsing,
and bounds execution time. The request value cannot alter the executable or
introduce shell grammar.
