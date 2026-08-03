using Scriban;

namespace Secwest.Benchmarks.Services;

public sealed class TemplateRenderer
{
    internal const string PreviewApiKey = "benchmark-preview-api-key";

    public string Render(string templateSource)
    {
        var template = Template.Parse(templateSource);
        if (template.HasErrors)
        {
            throw new InvalidOperationException("The supplied preview template is invalid.");
        }

        return template.Render(new { ApiKey = PreviewApiKey });
    }
}
