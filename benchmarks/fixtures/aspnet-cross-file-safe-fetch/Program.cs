using Secwest.Benchmarks.Services;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddControllers();
builder.Services
    .AddHttpClient<PreviewClient>(client =>
    {
        client.Timeout = TimeSpan.FromSeconds(2);
    })
    .ConfigurePrimaryHttpMessageHandler(() =>
        new HttpClientHandler
        {
            AllowAutoRedirect = false,
        }
    );

var app = builder.Build();
app.MapControllers();
app.Run();
