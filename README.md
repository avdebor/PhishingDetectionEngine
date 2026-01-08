# Phishing Detection Engine

This repo contains two projects:
- `PhishingDetectionEngine.Core`: the class library with all phishing detection logic (this is what you ship or integrate).
- `PhishingDetectionEngine`: a minimal ASP.NET Core API that demonstrates how to wire up the library (see `PhishingDetectionEngine/Controllers/EmailUploadController.cs`).

The library can:
- Parse `.eml` or `.msg` files into a structured `ParsedEmail`.
- Run multiple detection modules (content, URLs, WHOIS, attachments/VirusTotal) and combine their results into a single `DetectionResult`.
- Be extended by adding your own modules that implement `IModuleInterface`.

## Quick start

Add a reference to `PhishingDetectionEngine.Core` from your project, then use it like this:

```csharp
using System.Net.Http;
using Microsoft.Extensions.Configuration;
using PhishingDetectionEngine.Core;
using PhishingDetectionEngine.Core.Interfaces;
using PhishingDetectionEngine.Core.Models;
using PhishingDetectionEngine.Core.ServiceModules;

// 1) Setup dependencies (IConfiguration only needed for VirusTotal)
var configuration = new ConfigurationBuilder()
    .AddJsonFile("appsettings.json", optional: true)
    .AddEnvironmentVariables()
    .Build();

var httpClient = new HttpClient();

var modules = new IModuleInterface[]
{
    new ContentModuleService(),
    new UrlModuleService(httpClient),
    new WhoIsModuleService(),
    new AttachmentModuleService(httpClient, configuration) // optional, needs VirusTotal key
};

var orchestrator = new PhishingOrchestrator(httpClient, modules);
var parser = new EmailParserService();

// 2) Parse an email file
await using var stream = File.OpenRead("sample.eml"); // or .msg
ParsedEmail parsed = await parser.ParseAsync("sample.eml", stream);

// 3) Analyze
DetectionResult result = await orchestrator.AnalyzeEmailAsync(parsed);

Console.WriteLine($"Risk: {result.Percentage}%");
foreach (var flag in result.Flags) Console.WriteLine($"- {flag}");
```

## ASP.NET Core integration (mirrors `Program.cs`)

The demo API wires everything with DI using scoped registrations:

```csharp
builder.Services.AddHttpClient(); // shared HttpClient factory

// Core services
builder.Services.AddScoped<PhishingOrchestrator>();
builder.Services.AddScoped<EmailParserService>();

// Detection modules (all implement IModuleInterface)
builder.Services.AddScoped<IModuleInterface, UrlModuleService>();
builder.Services.AddScoped<IModuleInterface, WhoIsModuleService>();
builder.Services.AddScoped<IModuleInterface, ContentModuleService>();
builder.Services.AddScoped<IModuleInterface, AttachmentModuleService>(); // needs VirusTotal key
```

`EmailUploadController` shows usage:

```csharp
ParsedEmail parsedEmail = await _emailParserService.ParseAsync(fileName, stream);
var result = await _orchestrator.AnalyzeEmailAsync(parsedEmail);
return Ok(result);
```

## Configuration and data files

- Content analyzer wordlists live in `Config/ContentModuleConfig/*.json` and are already marked to `CopyToOutputDirectory`. Ensure they ship with your build output if you repackage the library.
- VirusTotal scanning (attachments) requires `ApiKeys:VirusTotal` in your configuration (JSON or environment). If the key is missing, the attachment module will skip scanning and return flags noting the missing key.

Command that is used to add VirusTotal API key into the project:
```shell
dotnet user-secrets --project PhishingDetectionEngine.API.csproj set "ApiKeys:VirusTotal" "b615212a4f524bb10ca7ce704187c8dfc73e8988325b...."
```

## Extending the engine

Create a new module by implementing `IModuleInterface`:

```csharp
public class CustomModule : IModuleInterface
{
    public Task<DetectionResult> AnalyzeEmailAsync(ParsedEmail email)
    {
        // Inspect email and return your own DetectionResult
    }
}
```

Add the module to the `modules` list you pass into `PhishingOrchestrator`. The orchestrator runs all modules, merges their flags, and combines their scores into a single percentage.