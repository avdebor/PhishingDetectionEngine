using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;
using PhishingDetectionEngine.Core.Models;
using PhishingDetectionEngine.Core.Interfaces;
using PhishingDetectionEngine.Core.Utilities;
using PhishingDetectionEngine.Core.Interaces;

namespace PhishingDetectionEngine.Core.ServiceModules
{
    public class PhishTankApiService : IPhishtankApiService
    {
        private readonly HttpClient _httpClient;
        private const string PhishTankEndpoint = "http://checkurl.dev.phishtank.com/checkurl/";

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
                // Extract URLs
                var urlsToCheck = EmailUrlExtractor.ExtractUrls(email);

                if (urlsToCheck.Count == 0)
                {
                    //return empty result if no URLs found
                    return detectionResult;
                }
                else 
                {
                    int phishingCount = 0;

                    foreach (var url in urlsToCheck)
                    {
                        // Make direct API call and parse JSON manually
                        var isPhishing = await CheckUrlWithPhishTank(url);

                        if (isPhishing)
                        {
                            detectionResult.Flags.Add($"Phishing URL detected: {url}");
                            phishingCount++;
                        }
                    }
                    // Calculate percentage
                    detectionResult.Percentage = urlsToCheck.Count > 0 ?
                        (phishingCount * 100) / urlsToCheck.Count : 0;

                    detectionResult.Flags.Add($"Scanned {urlsToCheck.Count} URLs, found {phishingCount} phishing");
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