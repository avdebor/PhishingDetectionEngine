using Microsoft.AspNetCore.Http.Features;
using Microsoft.OpenApi.Models;
using PhishingDetectionEngine.Core;
using PhishingDetectionEngine.Core.Interfaces;
using PhishingDetectionEngine.Core.ServiceModules;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// support legacy code pages (for some .msg parsing libraries)
Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);

// If you expect large uploads (zip or many emails), increase limits here.
// You can remove or lower these values if not needed.
builder.Services.Configure<FormOptions>(options =>
{
    options.MultipartBodyLengthLimit = 200 * 1024 * 1024; // 200 MB
    options.ValueLengthLimit = int.MaxValue;
    options.MultipartHeadersLengthLimit = int.MaxValue;
});

// Add controllers (uses System.Text.Json by default)
builder.Services.AddControllers();
builder.Services.AddScoped<PhishingOrchestrator>();
builder.Services.AddScoped<EmailParserService>();
builder.Services.AddScoped<IContentService, AnalyzeEmailContent>();


// Swagger / OpenAPI
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo
    {
        Title = "Phishing Detection Engine API",
        Version = "v1"
    });

    // Optionally, ensure file upload parameters are handled.
    // No extra packages required � Swashbuckle will map IFormFile
    // when it is used directly as [FromForm] IFormFile parameter.
});

builder.Services.AddHttpClient();
builder.Services.AddScoped<IUrlService, UrlService>();

var app = builder.Build();

// Swagger UI in development
if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
    app.UseSwagger();
    app.UseSwaggerUI(c =>
    {
        c.SwaggerEndpoint("/swagger/v1/swagger.json", "Phishing Detection Engine API v1");
        c.RoutePrefix = string.Empty; // Swagger UI served at app root
    });
}

app.UseHttpsRedirection();

app.UseAuthorization();

app.MapControllers();

app.Run();
