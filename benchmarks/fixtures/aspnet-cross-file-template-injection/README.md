# ASP.NET cross-file template-source injection

The controller passes attacker-controlled request data through a uniquely typed
service boundary into Scriban's template-source parser. The parsed template is
then rendered with a server-owned secret in scope.
