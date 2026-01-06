using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using PhishingDetectionEngine.Core.Interfaces;
using PhishingDetectionEngine.Core.Models;

namespace PhishingDetectionEngine.Core.ServiceModules
{
    public class AttachmentModuleService : IModuleInterface
    {
        private readonly HttpClient _httpClient;
        private const string VirusTotalApiBaseUrl = "https://www.virustotal.com/api/v3";
        private readonly string _apiKey;

        public AttachmentModuleService(HttpClient httpClient, IConfiguration configuration)
        {
            _httpClient = httpClient;
            _httpClient.Timeout = TimeSpan.FromSeconds(60);
            _apiKey = configuration["ApiKeys:VirusTotal"] ?? string.Empty;
        }

        public async Task<DetectionResult> AnalyzeEmailAsync(ParsedEmail email)
        {
            Console.WriteLine("VirusTotal API key:" + _apiKey);
            var detectionResult = new DetectionResult
            {
                EmailSubject = email?.Subject ?? "No subject",
                DateOfScan = DateTime.UtcNow,
                Flags = new List<string>(),
                Percentage = 0
            };

            if (email?.Attachments == null || !email.Attachments.Any())
            {
                detectionResult.Flags.Add("No attachments to scan");
                return detectionResult;
            }

            if (string.IsNullOrWhiteSpace(_apiKey))
            {
                detectionResult.Flags.Add("VirusTotal API key not configured");
                return detectionResult;
            }

            bool maliciousFound = false;

            foreach (var attachment in email.Attachments)
            {
                try
                {
                    var analysisResult = await SubmitAndAnalyzeAsync(attachment);

                    if (analysisResult.IsMalicious)
                    {
                        maliciousFound = true;
                        detectionResult.Flags.Add($"Malicious attachment detected by VirusTotal: {attachment.FileName}");
                    }
                    else
                    {
                        detectionResult.Flags.Add($"Attachment clean (VirusTotal): {attachment.FileName}");
                    }
                }
                catch (Exception ex)
                {
                    detectionResult.Flags.Add($"Error scanning attachment {attachment?.FileName ?? "unknown"}: {ex.Message}");
                }
            }

            if (maliciousFound)
            {
                detectionResult.Percentage = 100;
                detectionResult.Flags.Add("Malicious attachment content detected");
            }
            else
            {
                detectionResult.Percentage = 0;
                detectionResult.Flags.Add("No malicious attachments were found");
            }

            return detectionResult;
        }

        private async Task<VirusTotalAnalysisResult> SubmitAndAnalyzeAsync(EmailAttachment attachment)
        {
            Console.WriteLine("Attachment content:" + attachment?.Content);
            if (attachment?.Content == null || attachment.Content.Length == 0)
                throw new Exception("Attachment content is empty.");

            using var form = new MultipartFormDataContent();
            var fileContent = new ByteArrayContent(attachment.Content);

            fileContent.Headers.ContentType = new MediaTypeHeaderValue(
                string.IsNullOrWhiteSpace(attachment.ContentType)
                    ? "application/octet-stream"
                    : attachment.ContentType);

            form.Add(
                fileContent,
                "file",
                string.IsNullOrWhiteSpace(attachment.FileName) ? "attachment.bin" : attachment.FileName);

            using var uploadRequest = new HttpRequestMessage(HttpMethod.Post, $"{VirusTotalApiBaseUrl}/files");
            uploadRequest.Headers.Add("x-apikey", _apiKey);
            uploadRequest.Content = form;

            var uploadResponse = await _httpClient.SendAsync(uploadRequest);
            uploadResponse.EnsureSuccessStatusCode();

            var uploadJson = await uploadResponse.Content.ReadAsStringAsync();
            var analysisId = ExtractAnalysisId(uploadJson);

            if (string.IsNullOrWhiteSpace(analysisId))
                throw new Exception("VirusTotal did not return an analysis id.");

            // Poll VirusTotal until analysis is ready. Increase attempts to allow
            // larger files/slow queue; ~60s total with current delay.
            for (int attempt = 0; attempt < 15; attempt++)
            {
                using var analysisRequest = new HttpRequestMessage(HttpMethod.Get, $"{VirusTotalApiBaseUrl}/analyses/{analysisId}");
                analysisRequest.Headers.Add("x-apikey", _apiKey);

                var analysisResponse = await _httpClient.SendAsync(analysisRequest);
                analysisResponse.EnsureSuccessStatusCode();

                var analysisJson = await analysisResponse.Content.ReadAsStringAsync();
                var analysisResult = ExtractStats(analysisJson);

                if (analysisResult.Completed)
                    return analysisResult;

                await Task.Delay(TimeSpan.FromSeconds(4));
            }

            throw new Exception("VirusTotal analysis did not complete in time.");
        }

        private static string ExtractAnalysisId(string json)
        {
            using var document = JsonDocument.Parse(json);

            if (document.RootElement.TryGetProperty("data", out var dataElement) &&
                dataElement.TryGetProperty("id", out var idElement))
            {
                return idElement.GetString() ?? string.Empty;
            }

            return string.Empty;
        }

        private static VirusTotalAnalysisResult ExtractStats(string json)
        {
            using var document = JsonDocument.Parse(json);

            if (!document.RootElement.TryGetProperty("data", out var dataElement) ||
                !dataElement.TryGetProperty("attributes", out var attributesElement))
            {
                throw new Exception("VirusTotal analysis response missing attributes.");
            }

            var status = attributesElement.TryGetProperty("status", out var statusElement)
                ? statusElement.GetString()
                : string.Empty;

            var stats = attributesElement.TryGetProperty("stats", out var statsElement) ? statsElement : default;

            int malicious = 0;
            int suspicious = 0;

            if (stats.ValueKind == JsonValueKind.Object)
            {
                if (statsElement.TryGetProperty("malicious", out var maliciousElement))
                    malicious = maliciousElement.GetInt32();

                if (statsElement.TryGetProperty("suspicious", out var suspiciousElement))
                    suspicious = suspiciousElement.GetInt32();
            }

            bool completed = string.Equals(status, "completed", StringComparison.OrdinalIgnoreCase);
            bool isMalicious = malicious > 0 || suspicious > 0;

            return new VirusTotalAnalysisResult(completed, isMalicious, malicious, suspicious);
        }

        private record VirusTotalAnalysisResult(bool Completed, bool IsMalicious, int MaliciousCount, int SuspiciousCount);
    }
}