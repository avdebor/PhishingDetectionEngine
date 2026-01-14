using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;
using PhishingDetectionEngine.Core.Interfaces;
using PhishingDetectionEngine.Core.Models;

namespace PhishingDetectionEngine.Core
{
    public class PhishingOrchestrator
    {
        private readonly HttpClient _httpClient;
        private readonly List<IModuleInterface> _modules;

        public PhishingOrchestrator(HttpClient httpClient, IEnumerable<IModuleInterface> modules)
        {
            _httpClient = httpClient;
            _modules = modules.ToList();
        }

        public async Task<DetectionResult> AnalyzeEmailAsync(ParsedEmail parsedEmail)
        {
            var detectionTasks = _modules
                .Select(m => m.AnalyzeEmailAsync(parsedEmail))
                .ToList();

            var detectionResults = await Task.WhenAll(detectionTasks);

            var scores = detectionResults
                .Select(r => r.Percentage)
                .ToList();
            var combinedFlags = detectionResults
                .SelectMany(r => r.Flags)
                .Distinct()
                .ToList();

            int totalScore = CalculateOverallScore(scores);

            return new DetectionResult
            {
                EmailSubject = parsedEmail.Subject,
                Percentage = totalScore,
                Flags = combinedFlags,
                DateOfScan = DateTime.Now
            };
        }

        private int CalculateOverallScore(List<int> scores)
        {
            if (scores == null || scores.Count == 0)
                return 0;

            double product = 1.0;
            foreach (var s in scores)
            {
                var clamped = Math.Clamp(s, 0, 100);
                product *= (1 - clamped / 100.0);
            }

            double rawScore = 1 - product;

            double alpha = 1 + rawScore;

            double finalScore = Math.Pow(rawScore, alpha);

            int result = (int)Math.Ceiling(finalScore * 100);
            return result;
        }
    }
}
