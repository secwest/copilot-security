# Spring Java caller-owned command-list argv control

This topology-matched control creates the same mutable caller-owned list, passes
that exact list to `ProcessBuilder(List)`, retains an alias, clears and rebuilds
the list, and starts the process. It keeps request data in one ordinary `printf`
argument, so shell metacharacters remain inert data.
