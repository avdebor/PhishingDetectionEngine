using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using PhishingDetectionEngine.Core.Models;
using PhishingDetectionEngine.Core.Interfaces;
using PhishingDetectionEngine.Core.Utilities;

namespace PhishingDetectionEngine.Core.ServiceModules
{
    public class AnalyzeEmailContent : IContentService
    {
        private readonly HashSet<string> _suspiciousWordsDutch;
        private readonly HashSet<string> _suspiciousWordsEnglish;
        private readonly HashSet<string> _urgentActionWords;
        private readonly HashSet<string> _securityTerms;
        private readonly HashSet<string> _highlySuspiciousWords;

        public AnalyzeEmailContent()
        {

            _highlySuspiciousWords = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "mobiele nummer", "WhatsApp-nummer", "WhatsApp", "mobile number"
            };

            // Dutch suspicious words
            _suspiciousWordsDutch = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                 "telefoonnummer", "bankgegevens", "inloggegevens",
                "wachtwoord", "beveiligingscode", "verificatiecode", "sms code",
                "authenticatie", "account", "betaalgegevens", "creditcard",
                "pin code", "identiteitsbewijs", "bsn", "bsn nummer", "sofi nummer",
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
                "crypto", "password reset", "account recovery", "unlock account",
                "activate", "accept", "AI", "awards", "award", "security",
                "verification", "authentication", "validation",
                "confirm", "verify", "authenticate", "validate",
                "password", "pin", "code", "token",
                "2fa", "two factor", "multi factor", "biometric",
                "encryption", "secure", "protected", "safety", "securing",
                "start"
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
                "encryption", "secure", "protected", "safety", "securing"
            };
        }

        public async Task<DetectionResult> AnalyzeContent(ParsedEmail email)
        {
            Console.WriteLine(email.TextBody);

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
                
                string emailBody = TextFetcherFromHTMLContent.GetPlainTextFromHtmlContent(email.HtmlBody);
                var textToAnalyze = $"{email.Subject} {emailBody}";
                Console.WriteLine("email text body : " + email.TextBody);
                Console.WriteLine(String.IsNullOrEmpty(email.TextBody));      
                var foundWords = FindSuspiciousWords(textToAnalyze);
                var riskScore = CalculateRiskScore(foundWords, textToAnalyze);
                var hasPhoneNumber = ContainsPhoneNumber(emailBody);
                var hasHighlySusWords = ContainsHighlySuspiciousWords(emailBody);
                
                AddDetectionFlags(detectionResult, foundWords, riskScore, hasPhoneNumber, hasHighlySusWords);

                detectionResult.Percentage = riskScore;
            }
            catch (Exception ex)
            {
                detectionResult.Flags.Add($"Error during suspicious words analysis: {ex.Message}");
            }
            detectionResult.Percentage = Math.Min(detectionResult.Percentage, 100);
            return detectionResult;
        }

        private Dictionary<string, int> FindSuspiciousWords(string text)
        {
            var foundWords = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);

            string[] words = text.Split(' ');
            foreach (var word in words)
            {
                Console.WriteLine(word);
            }

            Console.WriteLine("------Dutch words------");
            foreach (var word in _suspiciousWordsDutch)
            {
                // Console.WriteLine(word);
                if (text.Contains(word, StringComparison.OrdinalIgnoreCase))
                {
                    foundWords[word] = GetWordRiskLevel(word);
                }
            }

            Console.WriteLine("------English words------");
            foreach (var word in _suspiciousWordsEnglish)
            {
                // Console.WriteLine(word);
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

            bool hasPhoneNumber = ContainsPhoneNumber(text);

            if (!foundWords.Any() && !hasPhoneNumber)
                return 0;

            bool hasUrgency = ContainsUrgentLanguage(text);
            bool hasHighlySusWords = ContainsHighlySuspiciousWords(text);

            // If ANY suspicious word is found, start at 20
            int score = 20;

            // Count occurrences or weight based on risk level
            int repetitionBonus = foundWords.Count * 5; // each word adds +10

            score += repetitionBonus;

            // If urgency + suspicious content -> maximum risk
            if (hasUrgency || hasHighlySusWords)
                return score += 40;

            if (hasPhoneNumber)
            {
                return 100;
            }

            // Cap at 95 to leave urgency as the only way to hit 100
            return Math.Min(score, 100);
        }


        private bool ContainsUrgentLanguage(string text)
        {
            var urgentPatterns = new[]
            {
                "immediately", "urgent", "right now", "act now",
                "dringend", "onmiddellijk", "nu handelen", "spoed"
            };

            return urgentPatterns.Any(pattern => 
                text.Contains(pattern, StringComparison.OrdinalIgnoreCase));
        }

        private bool ContainsHighlySuspiciousWords(string text)
        {
            if (string.IsNullOrWhiteSpace(text))
                return false;

            // Check if any of the "highly suspicious" phrases appear in the text
            return _highlySuspiciousWords.Any(word =>
                text.Contains(word, StringComparison.OrdinalIgnoreCase));
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

            return phonePatterns.Any(pattern =>
                System.Text.RegularExpressions.Regex.IsMatch(text, pattern, System.Text.RegularExpressions.RegexOptions.IgnoreCase));
        }


        private void AddDetectionFlags(DetectionResult result, Dictionary<string, int> foundWords, int riskScore, bool hasPhoneNumber, bool hasHighlySusWords)
        {
            
            if (!foundWords.Any() && !hasPhoneNumber)
            {
                result.Flags.Add("No suspicious words detected");
                return;
            }

            if (hasHighlySusWords)
            {
                result.Flags.Add("HIGHLY SUSPICIOUS WORDS FOUND (print the word later) :3");
            }


            if (hasPhoneNumber)
            {
                result.Flags.Add("HIGH RISK: Phone Number Found");
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