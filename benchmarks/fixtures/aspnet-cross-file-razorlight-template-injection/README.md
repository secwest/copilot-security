# ASP.NET cross-file RazorLight template injection

The request body crosses a typed controller/service boundary into the `content`
argument of `IRazorLightEngine.CompileRenderStringAsync`. The model contains a
server-owned secret, so attacker-controlled Razor source can disclose it.
