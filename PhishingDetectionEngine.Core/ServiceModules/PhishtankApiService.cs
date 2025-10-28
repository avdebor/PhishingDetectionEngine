using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;
using PhishingDetectionEngine.Core.Models;
using PhishingDetectionEngine.Core.Interfaces;
using PhishingDetectionEngine.Core.Utilities;

namespace PhishingDetectionEngine.Core.ServiceModules
{
    public class PhishTankApiService : IPhishtankApiService
    {
        private readonly HttpClient _httpClient;
        private const string PhishTankEndpoint = "http://checkurl.phishtank.com/checkurl/";

        private static readonly HashSet<string> KnownSafeMsgUrls= new()
        {
            "http://schemas.microsoft.com/office/2004/12/omml",
            "http://www.w3.org/TR/REC-html40"
        };

        public PhishTankApiService(HttpClient httpClient)
        {
            _httpClient = httpClient;
            _httpClient.Timeout = TimeSpan.FromSeconds(30);
        }

        public async Task<DetectionResult> PerformLookup(ParsedEmail email)
        {
            var detectionResult = new DetectionResult
            {
                EmailSubject = email?.Subject ?? "No subject",
                DateOfScan = DateTime.UtcNow,
                Flags = new List<string>(),
                Percentage = 0
            };

            try
            {
                // Extract URLs + filter known safe URLs
                var urlsToCheck = EmailUrlExtractor.ExtractUrls(email)
                    .Where(u => !string.IsNullOrWhiteSpace(u) && 
                    Uri.IsWellFormedUriString(u, UriKind.Absolute) &&
                    !KnownSafeMsgUrls.Contains(u))
                    .Distinct()
                    .ToList();

                if (!urlsToCheck.Any())
                {
                    // Return empty result if no URLs found
                    return detectionResult;
                }
                else
                {
                    // Check all URLs asynchronously
                    var phishingResults = await Task.WhenAll(urlsToCheck.Select(async url => new
                    {
                        Url = url,
                        IsPhishing = await CheckUrlWithPhishTank(url)
                    }));

                    // Collect phishing URLs
                    var phishingUrls = phishingResults
                        .Where(r => r.IsPhishing)
                        .Select(r => r.Url)
                        .ToList();

                    // Add detection flags
                    phishingUrls.ForEach(url => detectionResult.Flags.Add($"Phishing URL detected: {url}"));
                    detectionResult.Flags.Add($"Scanned {urlsToCheck.Count} URLs");

                    // Set percentage (100% if any phishing found)
                    detectionResult.Percentage = phishingUrls.Any() ? 100 : 0;
                }
            }
            catch (Exception ex)
            {
                detectionResult.Flags.Add($"Error during PhishTank scan: {ex.Message}");
            }
            return detectionResult;
        }
        private async Task<bool> CheckUrlWithPhishTank(string url)
        {
            try
            {
                var formData = new List<KeyValuePair<string, string>>
                {
                    new("url", url),
                    new("format", "json")
                };

                var content = new FormUrlEncodedContent(formData);
                var response = await _httpClient.PostAsync(PhishTankEndpoint, content);

                if (response.IsSuccessStatusCode)
                {
                    var jsonResponse = await response.Content.ReadAsStringAsync();

                    using var jsonDoc = JsonDocument.Parse(jsonResponse);
                    if (jsonDoc.RootElement.TryGetProperty("results", out var results))
                    {
                        if (results.TryGetProperty("in_database", out var inDatabase) &&
                            results.TryGetProperty("valid", out var valid))
                        {
                            // in_database is boolean, valid is string "y"/"n"
                            bool isInDatabase = inDatabase.GetBoolean();
                            bool isValid = valid.GetString() == "y";

                            return isInDatabase && isValid;
                        }
                    }
                }
            }
            catch
            {
                throw new Exception("Error communicating with PhishTank API");
            }

            return false;
        }
    }
}