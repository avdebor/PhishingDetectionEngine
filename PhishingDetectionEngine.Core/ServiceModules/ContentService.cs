using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using PhishingDetectionEngine.Core.Models;
using PhishingDetectionEngine.Core.Interfaces;

namespace PhishingDetectionEngine.Core.ServiceModules
{
    public class AnalyzeEmailContent : IContentService
    {
        private readonly HashSet<string> _suspiciousWordsDutch;
        private readonly HashSet<string> _suspiciousWordsEnglish;
        private readonly HashSet<string> _urgentActionWords;
        private readonly HashSet<string> _securityTerms;

        public AnalyzeEmailContent()
        {
            // Dutch suspicious words
            _suspiciousWordsDutch = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "mobiele nummer", "telefoonnummer", "bankgegevens", "inloggegevens",
                "wachtwoord", "beveiligingscode", "verificatiecode", "sms code",
                "authenticatie", "account", "betaalgegevens", "creditcard",
                "pin code", "identiteitsbewijs", "bsn nummer", "sofi nummer",
                "herinnering", "dringend", "onmiddellijk", "dringende actie",
                "bevestiging", "update", "onderhoud", "probleem",
                "verdacht", "ongebruikelijk", "activiteit", "inbreuk",
                "beveiliging", "veiligheid", "opschorten", "blokkeren",
                "verlopen", "verlopen", "aankoop", "factuur",
                "betaling", "transactie", "overschrijving", "limiet",
                "premie", "korting", "aanbieding", "winnaar",
                "prijs", "lottery", "geluksvogel", "gratis",
                "urgent", "belangrijk", "aandacht", "waarschuwing"
            };

            // English suspicious words
            _suspiciousWordsEnglish = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "login", "verification", "password", "credentials",
                "account", "security", "verify", "authentication",
                "confirmation", "update", "maintenance", "problem",
                "suspicious", "unusual", "activity", "breach",
                "security", "safety", "suspend", "block",
                "expire", "expired", "purchase", "invoice",
                "payment", "transaction", "transfer", "limit",
                "premium", "discount", "offer", "winner",
                "prize", "lottery", "lucky", "free",
                "urgent", "important", "attention", "warning",
                "immediately", "action required", "click here", "update now",
                "confirm your", "validate your", "secure your", "protect your",
                "banking", "financial", "personal information", "social security",
                "credit card", "debit card", "paypal", "bitcoin",
                "crypto", "password reset", "account recovery", "unlock account"
            };

            // Urgent action words
            _urgentActionWords = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "immediately", "urgent", "now", "right away",
                "instant", "quick", "fast", "hurry",
                "deadline", "limited time", "last chance", "final warning",
                "action required", "immediate action", "respond now", "click immediately"
            };

            // Security-related terms
            _securityTerms = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "security", "verification", "authentication", "validation",
                "confirm", "verify", "authenticate", "validate",
                "password", "pin", "code", "token",
                "2fa", "two factor", "multi factor", "biometric",
                "encryption", "secure", "protected", "safety"
            };
        }

        public async Task<DetectionResult> AnalyzeContent(ParsedEmail email)
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
                if (email == null || (string.IsNullOrEmpty(email.TextBody) && string.IsNullOrEmpty(email.Subject)))
                {
                    detectionResult.Flags.Add("No email content to analyze for suspicious words");
                    return detectionResult;
                }

                var textToAnalyze = $"{email.Subject} {email.TextBody}";                
                var foundWords = FindSuspiciousWords(textToAnalyze);
                var riskScore = CalculateRiskScore(foundWords, textToAnalyze);
                
                AddDetectionFlags(detectionResult, foundWords, riskScore);

                detectionResult.Percentage = riskScore;
            }
            catch (Exception ex)
            {
                detectionResult.Flags.Add($"Error during suspicious words analysis: {ex.Message}");
            }

            return detectionResult;
        }

        private Dictionary<string, int> FindSuspiciousWords(string text)
        {
            var foundWords = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            
            foreach (var word in _suspiciousWordsDutch)
            {
                if (text.Contains(word, StringComparison.OrdinalIgnoreCase))
                {
                    foundWords[word] = GetWordRiskLevel(word);
                }
            }

            foreach (var word in _suspiciousWordsEnglish)
            {
                if (text.Contains(word, StringComparison.OrdinalIgnoreCase))
                {
                    foundWords[word] = GetWordRiskLevel(word);
                }
            }

            return foundWords;
        }

        private int GetWordRiskLevel(string word)
        {
            // High risk words
            if (_urgentActionWords.Contains(word) || 
                word.Contains("password") || 
                word.Contains("wachtwoord") ||
                word.Contains("bank") ||
                word.Contains("creditcard") ||
                word.Contains("bsn"))
            {
                return 3; // High risk
            }

            // Medium risk words
            if (_securityTerms.Contains(word) ||
                word.Contains("verificatie") ||
                word.Contains("verification") ||
                word.Contains("login") ||
                word.Contains("inlog"))
            {
                return 2;
            }

            return 1;
        }

        private int CalculateRiskScore(Dictionary<string, int> foundWords, string text)
        {
            if (!foundWords.Any())
                return 0;

            int baseScore = 0;
            foreach (var word in foundWords)
            {
                baseScore += word.Value * 5;
            }

            int highRiskWordCount = foundWords.Count(w => w.Value >= 2);
            if (highRiskWordCount >= 3)
            {
                baseScore += 20;
            }

            if (ContainsUrgentLanguage(text))
            {
                baseScore += 15;
            }

            return Math.Min(baseScore, 100);
        }

        private bool ContainsUrgentLanguage(string text)
        {
            var urgentPatterns = new[]
            {
                "immediately", "urgent", "right now", "act now",
                "dringend", "onmiddellijk", "nu handelen"
            };

            return urgentPatterns.Any(pattern => 
                text.Contains(pattern, StringComparison.OrdinalIgnoreCase));
        }

        private void AddDetectionFlags(DetectionResult result, Dictionary<string, int> foundWords, int riskScore)
        {
            if (!foundWords.Any())
            {
                result.Flags.Add("No suspicious words detected");
                return;
            }

            result.Flags.Add($"Found {foundWords.Count} suspicious word(s)");

            var highRiskWords = foundWords.Where(w => w.Value >= 2).ToList();
            if (highRiskWords.Any())
            {
                result.Flags.Add($"High-risk words detected: {string.Join(", ", highRiskWords.Select(w => w.Key))}");
            }

            var mediumRiskWords = foundWords.Where(w => w.Value == 1).ToList();
            if (mediumRiskWords.Any())
            {
                result.Flags.Add($"Suspicious words detected: {string.Join(", ", mediumRiskWords.Select(w => w.Key))}");
            }

            if (riskScore >= 70)
            {
                result.Flags.Add("HIGH RISK: Multiple high-risk suspicious words detected");
            }
            else if (riskScore >= 40)
            {
                result.Flags.Add("MEDIUM RISK: Suspicious words patterns detected");
            }
            else if (riskScore > 0)
            {
                result.Flags.Add("LOW RISK: Minor suspicious content detected");
            }
        }
    }
}