# ASP.NET cross-file command injection

The controller passes a query parameter through a constructor-injected service
into the argument string of `ProcessStartInfo` for `cmd.exe /c`.
