# Vulnerable Shescape CMD boundary

An Express query value crosses three relative-module calls before Shescape 3.0.0 escapes it for `cmd.exe` and the result reaches an official Node child-process shell dispatcher. This version fails to escape parentheses, so CMD can leave the intended parenthesized command group.

The witness uses only the advisory's fixed conditional and `echo y`. On Windows it confirms the injected branch through the public `Shescape` API and captured standard output. On other platforms it imports the published package's exact internal Windows CMD escape function through its resolved file URL and checks that boundary without invoking a shell. It opens no listener, reads no application data, writes no file, makes no network request, and changes no persistent state.
