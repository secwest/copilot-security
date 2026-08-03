using RazorLight;

namespace Secwest.Benchmarks.Services;

public sealed class RazorTemplateRenderer
{
    internal const string PreviewApiKey = "benchmark-preview-api-key";

    private readonly IRazorLightEngine _engine = new RazorLightEngineBuilder()
        .UseEmbeddedResourcesProject(typeof(RazorTemplateRenderer))
        .SetOperatingAssembly(typeof(RazorTemplateRenderer).Assembly)
        .UseMemoryCachingProvider()
        .Build();

    public Task<string> RenderAsync(string templateSource)
    {
        return _engine.CompileRenderStringAsync(
            Guid.NewGuid().ToString("N"),
            templateSource,
            new { ApiKey = PreviewApiKey });
    }
}
