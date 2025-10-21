using Microsoft.OpenApi.Models;
using PhishingDetectionEngine.Core.Interfaces;
using PhishingDetectionEngine.Core.Services;

var builder = WebApplication.CreateBuilder(args);

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
