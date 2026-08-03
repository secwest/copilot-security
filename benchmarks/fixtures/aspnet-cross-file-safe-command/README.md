# ASP.NET cross-file safe command

The controller passes an untrusted host through the same service boundary, but
the service starts a fixed executable without a shell and adds the value as one
argument through `ProcessStartInfo.ArgumentList`.
