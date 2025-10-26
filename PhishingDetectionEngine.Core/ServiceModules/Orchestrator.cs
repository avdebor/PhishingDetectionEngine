using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using PhishingDetectionEngine.Core.Models;
using PhishingDetectionEngine.Core.Services;

namespace PhishingDetectionEngine.Core
{
    public class PhishingOrchestrator
    {
        private readonly EmailParserService _emailParser;

        public PhishingOrchestrator()
        {
            _emailParser = new EmailParserService();
        }

        public async Task<PhishingResult> AnalyzeEmailAsync(string fileName, Stream emailStream)
        {
            var parsedEmail = await _emailParser.ParseAsync(fileName, emailStream);

            var moduleScores = new List<ModuleScore>();

            double basicScore = CalculatePhishingScore(parsedEmail);
            moduleScores.Add(new ModuleScore { ModuleName = "BasicHeuristicModule", Score = basicScore });

            double overallScore = CalculateOverallScore(moduleScores.Select(m => m.Score).ToList());

            return new PhishingResult
            {
                OverallScore = overallScore,
                ModuleScores = moduleScores
            };
        }

        private double CalculatePhishingScore(ParsedEmail email)
        {
            double score = 0;

            if (email.Subject.Contains("urgent", StringComparison.OrdinalIgnoreCase)) score += 20;
            if (email.Subject.Contains("verify", StringComparison.OrdinalIgnoreCase)) score += 20;
            if (email.TextBody.Contains("click here", StringComparison.OrdinalIgnoreCase)) score += 20;
            if (email.TextBody.Contains("password", StringComparison.OrdinalIgnoreCase)) score += 20;
            if (email.From.Contains("@unknown-domain.com", StringComparison.OrdinalIgnoreCase)) score += 20;

            return Math.Min(score, 100);
        }

        private double CalculateOverallScore(List<double> scores)
        {
            if (scores == null || scores.Count == 0)
                return 0;

            double product = 1;
            foreach (var s in scores)
            {
                product *= (1 - s / 100.0);
            }

            double result = (1 - product) * 100;
            return Math.Round(result, 2);
        }
    }
}
