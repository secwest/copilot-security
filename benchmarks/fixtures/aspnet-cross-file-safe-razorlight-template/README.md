# ASP.NET cross-file safe RazorLight template

The service compiles fixed server-owned Razor source. The request body and the
same server-owned secret are supplied only as model properties, so attacker
text is encoded data and is never compiled as Razor grammar.
