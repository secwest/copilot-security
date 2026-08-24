# Repaired Shescape CMD boundary

This source-identical control changes only Shescape from 3.0.0 to 3.0.1. The repaired Windows CMD escaper prefixes both parentheses with carets, so the value remains inside the intended parenthesized command group.

The witness uses only the advisory's fixed conditional and `echo y`. On Windows it confirms through the public `Shescape` API and captured standard output that no injected branch runs. On other platforms it imports the published package's exact internal Windows CMD escape function through its resolved file URL and checks that boundary without invoking a shell. It opens no listener, reads no application data, writes no file, makes no network request, and changes no persistent state.
