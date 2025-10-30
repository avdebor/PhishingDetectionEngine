using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;
using PhishingDetectionEngine.Core.Models;
using PhishingDetectionEngine.Core.ServiceModules;

namespace PhishingDetectionEngine.Core
{
    public class PhishingOrchestrator
    {
        private readonly PhishTankApiService _phishTankApiService;
        private readonly HttpClient _httpClient;

        public PhishingOrchestrator()
        {
            _httpClient = new HttpClient();
            _phishTankApiService = new PhishTankApiService(_httpClient);
        }

        public async Task<DetectionResult> AnalyzeEmailAsync(ParsedEmail parsedEmail)
        {           
            var detectionTasks = new List<Task<DetectionResult>>
            {
                _phishTankApiService.PerformLookup(parsedEmail)
            };

            var detectionResults = await Task.WhenAll(detectionTasks);

            List<int> scores = new List<int>();

            foreach (var result in detectionResults)
            {
                scores.Add(result.Percentage);
            }

            List<string> combinedFlags = new List<string>();

            foreach (var result in detectionResults)
            {
                foreach (var flag in result.Flags)
                {
                    if (!combinedFlags.Contains(flag))
                    {
                        combinedFlags.Add(flag);
                    }
                }
            }

            int totalScore = CalculateOverallScore(scores);

            DetectionResult finalDetectionResult = new DetectionResult
            {
                EmailSubject = parsedEmail.Subject,
                Percentage = totalScore,
                Flags = combinedFlags,
                DateOfScan = DateTime.Now
            };

            return finalDetectionResult;
        }

        private int CalculateOverallScore(List<int> scores)
        {
            if (scores == null || scores.Count == 0)
                return 0;

            double product = 1;
            foreach (var s in scores)
                product *= (1 - s / 100.0);

            int result = (int)Math.Round((1 - product) * 100);
            return result;
        }
    }
}
