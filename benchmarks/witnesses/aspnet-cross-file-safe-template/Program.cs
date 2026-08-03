using Secwest.Benchmarks.Services;

var renderer = new TemplateRenderer();
var attackerName = "{{ api_key }}";
var output = renderer.Render(attackerName);

if (!output.Contains(attackerName, StringComparison.Ordinal) ||
    output.Contains(TemplateRenderer.PreviewApiKey, StringComparison.Ordinal))
{
    throw new InvalidOperationException("Expected attacker data to remain data under the fixed template.");
}

Console.WriteLine("Safe Scriban witness kept attacker input out of template source.");
