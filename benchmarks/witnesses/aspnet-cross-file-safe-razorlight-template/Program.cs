using Secwest.Benchmarks.Services;

var renderer = new RazorTemplateRenderer();
var attackerName = "@Model.ApiKey";
var output = await renderer.RenderAsync(attackerName);

if (!output.Contains(attackerName, StringComparison.Ordinal) ||
    output.Contains(RazorTemplateRenderer.PreviewApiKey, StringComparison.Ordinal))
{
    throw new InvalidOperationException("Expected attacker data to remain data under fixed Razor source.");
}

Console.WriteLine("Safe RazorLight witness kept attacker input out of template source.");
