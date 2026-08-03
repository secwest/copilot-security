using Secwest.Benchmarks.Services;

var renderer = new RazorTemplateRenderer();
var output = await renderer.RenderAsync("@Model.ApiKey");

if (output != RazorTemplateRenderer.PreviewApiKey)
{
    throw new InvalidOperationException("Expected attacker-controlled Razor source to disclose the model secret.");
}

Console.WriteLine("Vulnerable RazorLight witness disclosed the server-owned model secret.");
