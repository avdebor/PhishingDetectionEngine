using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;
using System.Linq;
using PhishingDetectionEngine.Core.Models;
using PhishingDetectionEngine.Core.Interfaces;
using PhishingDetectionEngine.Core.Utilities;

namespace PhishingDetectionEngine.Core.ServiceModules
{
    public class UrlService : IUrlService
    {
        private readonly HttpClient _httpClient;
        private const string PhishStatsApiUrl = "https://api.phishstats.info/api/phishing";

        private static readonly HashSet<string> KnownSafeMsgUrls = new()
        {
            "http://schemas.microsoft.com/office/2004/12/omml",
            "http://www.w3.org/TR/REC-html40"
        };

        public UrlService(HttpClient httpClient)
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
                    detectionResult.Flags.Add("No URLs to scan");
                    return detectionResult;
                }

                // Check all URLs asynchronously using PhishStats
                var phishingResults = await Task.WhenAll(urlsToCheck.Select(async url => new
                {
                    Url = url,
                    IsPhishing = await CheckUrlWithPhishStats(url)
                }));

                // Collect phishing URLs
                var phishingUrls = phishingResults
                    .Where(r => r.IsPhishing)
                    .Select(r => r.Url)
                    .ToList();

                // Add detection flags
                foreach (var result in phishingResults)
                {
                    if (result.IsPhishing)
                    {
                        detectionResult.Flags.Add($"Phishing Confirmed by PhishStats: {result.Url}");
                    }
                    else
                    {
                        detectionResult.Flags.Add($"Not present in PhishStats database, possibly phishing: {result.Url}");
                    }
                }

                detectionResult.Flags.Add($"Scanned {urlsToCheck.Count} URL(s) using PhishStats");

                // Set percentage (100% if any phishing found)
                detectionResult.Percentage = phishingUrls.Any() ? 100 : 50;
                
                if (detectionResult.Percentage == 25)
                {
                    detectionResult.Flags.Add("No phishing URLs detected in PhishStats database");
                }
                else
                {
                    detectionResult.Flags.Add($"Phishing detected by PhishStats: {phishingUrls.Count} URL(s) flagged");
                }
            }
            catch (Exception ex)
            {
                detectionResult.Flags.Add($"Error during PhishStats scan: {ex.Message}");
            }
            
            return detectionResult;
        }

        private async Task<bool> CheckUrlWithPhishStats(string url)
        {
            try
            {
                var apiUrl = $"{PhishStatsApiUrl}?_where=(url,eq,{Uri.EscapeDataString(url)})";
                var response = await _httpClient.GetStringAsync(apiUrl);
                
                // If response is not empty array and has content, it's phishing
                return !response.Trim().Equals("[]") && response.Length > 10;
            }
            catch (Exception ex)
            {
                throw new Exception($"Error checking URL with PhishStats: {ex.Message}");
            }
        }
    }
}