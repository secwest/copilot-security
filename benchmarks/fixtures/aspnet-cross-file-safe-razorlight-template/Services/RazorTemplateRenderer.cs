using RazorLight;

namespace Secwest.Benchmarks.Services;

public sealed class RazorTemplateRenderer
{
    internal const string PreviewApiKey = "benchmark-preview-api-key";
    private const string PreviewTemplate = "<p>Hello @Model.Name</p>";

    private readonly IRazorLightEngine _engine = new RazorLightEngineBuilder()
        .UseEmbeddedResourcesProject(typeof(RazorTemplateRenderer))
        .SetOperatingAssembly(typeof(RazorTemplateRenderer).Assembly)
        .UseMemoryCachingProvider()
        .Build();

    public Task<string> RenderAsync(string name)
    {
        return _engine.CompileRenderStringAsync(
            "fixed-preview-template",
            PreviewTemplate,
            new { Name = name, ApiKey = PreviewApiKey });
    }
}
