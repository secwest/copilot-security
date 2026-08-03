using Scriban;

namespace Secwest.Benchmarks.Services;

public sealed class TemplateRenderer
{
    internal const string PreviewApiKey = "benchmark-preview-api-key";
    private const string PreviewTemplate = "<p>Hello {{ name }}</p>";

    public string Render(string name)
    {
        var template = Template.Parse(PreviewTemplate);
        if (template.HasErrors)
        {
            throw new InvalidOperationException("The fixed preview template is invalid.");
        }

        return template.Render(new { Name = name, ApiKey = PreviewApiKey });
    }
}
