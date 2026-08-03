# ASP.NET cross-file fixed template

The matching controller and service topology parses only fixed server-owned
template source. Attacker-controlled data is supplied as one render-model
field and is not parsed a second time, even though a secret is also present in
the model.
