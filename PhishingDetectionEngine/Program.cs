using Microsoft.OpenApi.Models;
using PhishingDetectionEngine.Core.Interfaces;
using PhishingDetectionEngine.Core.ServiceModules;
using PhishingDetectionEngine.Core.Services;
using System.Text;

var builder = WebApplication.CreateBuilder(args);
Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);

builder.Services.AddScoped<IEmailParserService, EmailParserService>();

// Add services to the container.
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo
    {
        Title = "Phishing Detection Engine API",
        Version = "v1"
    });
});

builder.Services.AddHttpClient();
builder.Services.AddScoped<IPhishtankApiService, PhishTankApiService>();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI(c =>
    {
        c.SwaggerEndpoint("/swagger/v1/swagger.json", "Phishing Detection Engine API v1");
        c.RoutePrefix = string.Empty; // Makes Swagger UI open at root URL
    });
}

app.UseHttpsRedirection();

app.UseAuthorization();

app.MapControllers();
app.Run();
