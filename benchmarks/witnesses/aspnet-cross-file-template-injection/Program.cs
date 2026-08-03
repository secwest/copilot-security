using Secwest.Benchmarks.Services;

var renderer = new TemplateRenderer();
var output = renderer.Render("{{ api_key }}");

if (output != TemplateRenderer.PreviewApiKey)
{
    throw new InvalidOperationException("Expected attacker-controlled template source to disclose the model secret.");
}

Console.WriteLine("Vulnerable Scriban witness disclosed the server-owned model secret.");
