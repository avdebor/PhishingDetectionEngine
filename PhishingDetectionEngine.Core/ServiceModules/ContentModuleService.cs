using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Text.Json;
using System.IO;
using PhishingDetectionEngine.Core.Models;
using PhishingDetectionEngine.Core.Interfaces;
using PhishingDetectionEngine.Core.Utilities;

namespace PhishingDetectionEngine.Core.ServiceModules
{
    public class ContentModuleService : IModuleInterface
    {
        private readonly HashSet<string> _suspiciousWordsDutch;
        private readonly HashSet<string> _suspiciousWordsEnglish;
        private readonly HashSet<string> _urgentActionWords;
        private readonly HashSet<string> _securityTerms;
        private readonly HashSet<string> _highlySuspiciousWords;

        public ContentModuleService()
        {
            _highlySuspiciousWords = LoadWordListFromJson("Config/ContentModuleConfig/highlySuspiciousWords.json");
            _suspiciousWordsDutch = LoadWordListFromJson("Config/ContentModuleConfig/suspiciousWordsDutch.json");
            _suspiciousWordsEnglish = LoadWordListFromJson("Config/ContentModuleConfig/suspiciousWordsEnglish.json");
            _urgentActionWords = LoadWordListFromJson("Config/ContentModuleConfig/urgentActionWords.json");
            _securityTerms = LoadWordListFromJson("Config/ContentModuleConfig/securityTerms.json");
        }

        private HashSet<string> LoadWordListFromJson(string configPath)
        {
            try
            {
                // Try to get the file from the current directory (for development) or from the assembly location
                string filePath = configPath;
                
                // If file doesn't exist in current directory, try to find it relative to the assembly
                if (!File.Exists(filePath))
                {
                    var assemblyLocation = System.Reflection.Assembly.GetExecutingAssembly().Location;
                    var assemblyDirectory = Path.GetDirectoryName(assemblyLocation);
                    if (!string.IsNullOrEmpty(assemblyDirectory))
                    {
                        filePath = Path.Combine(assemblyDirectory, configPath);
                    }
                }

                if (File.Exists(filePath))
                {
                    var jsonContent = File.ReadAllText(filePath);
                    var words = JsonSerializer.Deserialize<List<string>>(jsonContent);
                    var wordCount = words?.Count ?? 0;
                    Console.WriteLine($"Successfully loaded words from {configPath}");
                    return new HashSet<string>(words ?? new List<string>(), StringComparer.OrdinalIgnoreCase);
                }
                else
                {
                    // Fallback: return empty HashSet if file not found and log the error
                    Console.WriteLine("No configuration files found for Content module");
                    return new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                }
            }
            catch (Exception ex)
            {
                // Fallback: return empty HashSet on error
                Console.WriteLine($"Error loading configuration file {configPath}: {ex.Message}");
                return new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            }
        }

        public async Task<DetectionResult> AnalyzeEmailAsync(ParsedEmail email)
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
                if (email == null || (string.IsNullOrWhiteSpace(email.TextBody) && string.IsNullOrWhiteSpace(email.Subject)))
                {
                    detectionResult.Flags.Add("No email content to analyze.");
                    return detectionResult;
                }

                string htmlPlainText = TextFetcherFromHTMLContent.GetPlainTextFromHtmlContent(email.HtmlBody);
                string textToAnalyze = string.Join(" ",
                    new[] { email.Subject, htmlPlainText, email.TextBody }
                    .Where(s => !string.IsNullOrWhiteSpace(s)));

                textToAnalyze = textToAnalyze ?? string.Empty;


                bool hasPhoneNumber = ContainsPhoneNumber(textToAnalyze);
                var highlySuspiciousMatches = FindMatches(textToAnalyze, _highlySuspiciousWords);
                var urgentMatches = FindMatches(textToAnalyze, _urgentActionWords);
                var securityMatches = FindMatches(textToAnalyze, _securityTerms);
                var suspiciousDutchMatches = FindMatches(textToAnalyze, _suspiciousWordsDutch);
                var suspiciousEnglishMatches = FindMatches(textToAnalyze, _suspiciousWordsEnglish);

                //add the flagss and calculate score

                AddFlags(detectionResult,hasPhoneNumber,highlySuspiciousMatches,urgentMatches,securityMatches,suspiciousDutchMatches,suspiciousEnglishMatches);
                detectionResult.Percentage = CalculateScore(hasPhoneNumber,highlySuspiciousMatches,urgentMatches,securityMatches,suspiciousDutchMatches,suspiciousEnglishMatches);
            }
            catch (Exception ex)
            {
                detectionResult.Flags.Add($"Error during suspicious content analysis: {ex.Message}");
            }

            return detectionResult;
        }

        private static List<string> FindMatches(string text, HashSet<string> phrases)
        {
            if (string.IsNullOrWhiteSpace(text))
                return new List<string>();

            return phrases
                .Where(p => text.Contains(p, StringComparison.OrdinalIgnoreCase))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();
        }

        private bool ContainsPhoneNumber(string text)
        {
            if (string.IsNullOrWhiteSpace(text))
                return false;

            var phonePatterns = new[]
            {
                @"(?:\+|00)\d{2}\s*(?:\(\s*0\s*\))?\s*[\d\-\s]{6,}",
                @"\b0\d{1,3}[\s\-]?\d{6,8}\b",
                @"\b\d{10,}\b"
            };

            return phonePatterns.Any(pattern =>System.Text.RegularExpressions.Regex.IsMatch(text,pattern,System.Text.RegularExpressions.RegexOptions.IgnoreCase));
        }

        private void AddFlags(DetectionResult result, bool hasPhoneNumber, List<string> highlySuspicious, List<string> urgent, List<string> security, List<string> suspiciousDutch, List<string> suspiciousEnglish)
        {
            bool hasAnySuspicious =
                hasPhoneNumber ||
                highlySuspicious.Any() ||
                urgent.Any() ||
                security.Any() ||
                suspiciousDutch.Any() ||
                suspiciousEnglish.Any();

            if (!hasAnySuspicious)
            {
                result.Flags.Add("No suspicious words, phrases or patterns detected.");
                return;
            }

            if (hasPhoneNumber)
            {
                result.Flags.Add("HIGH RISK: Phone number detected in the email content.");
            }

            if (highlySuspicious.Any())
            {
                result.Flags.Add("Highly suspicious contact-related wording detected: " +
                                 string.Join(", ", highlySuspicious));
            }

            if (urgent.Any())
            {
                result.Flags.Add("Urgent / pressure language detected: " +
                                 string.Join(", ", urgent));
            }

            if (security.Any())
            {
                result.Flags.Add("Security / access related terms detected: " +
                                 string.Join(", ", security));
            }

            if (suspiciousDutch.Any())
            {
                result.Flags.Add("Suspicious Dutch terms detected: " +
                                 string.Join(", ", suspiciousDutch));
            }

            if (suspiciousEnglish.Any())
            {
                result.Flags.Add("Suspicious English terms detected: " +
                                 string.Join(", ", suspiciousEnglish));
            }
        }

        private int CalculateScore(bool hasPhoneNumber, List<string> highlySuspicious, List<string> urgent, List<string> security, List<string> suspiciousDutch, List<string> suspiciousEnglish){
            //phone number = always 100
            if (hasPhoneNumber)
                return 100;

            //making new hashsets to ignore the duplicates
            var highSet = new HashSet<string>(highlySuspicious, StringComparer.OrdinalIgnoreCase);
            var urgentSet = new HashSet<string>(urgent, StringComparer.OrdinalIgnoreCase);
            var securitySet = new HashSet<string>(security, StringComparer.OrdinalIgnoreCase);
            var dutchSet = new HashSet<string>(suspiciousDutch, StringComparer.OrdinalIgnoreCase);
            var englishSet = new HashSet<string>(suspiciousEnglish, StringComparer.OrdinalIgnoreCase);
            //this is for both english and dutch normally suspicous words
            var normalSet = new HashSet<string>(securitySet, StringComparer.OrdinalIgnoreCase);


            normalSet.UnionWith(dutchSet);
            normalSet.UnionWith(englishSet);

            normalSet.ExceptWith(highSet);
            normalSet.ExceptWith(urgentSet);

            int normalCount = normalSet.Count;
            int highCount = highSet.Count;
            int urgentCount = urgentSet.Count;

            bool anySuspicious = (normalCount + highCount + urgentCount) > 0;
            if (!anySuspicious)
                return 0;

            int score = 0;

            // Any suspicious words = start at 20
            score += 20;

            // Urgency or highly suspicious word +30
            if (urgentCount > 0 || highCount > 0)
                score += 30;

            // every normaly suspicious word after the first one +5
            int extraNormal = Math.Max(0, normalCount - 1);
            score += extraNormal * 5;

            //every highly suspicious word after the first one +10
            if (highCount > 1)
            {
                int extraHigh = highCount - 1;
                score += extraHigh * 10;
            }

            //cap at 100
            return Math.Min(score, 100);
        }
    }
}
