using PhishingDetectionEngine.Core.Interfaces;
using PhishingDetectionEngine.Core.Models;
using PhishingDetectionEngine.Core.Utilities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using Whois;

namespace PhishingDetectionEngine.Core.ServiceModules
{
    public class WhoIsService : IWhoIsService
    {
        private readonly WhoisLookup _whoisLookup;

        public WhoIsService()
        {
            _whoisLookup = new WhoisLookup();
        }

        public async Task<DetectionResult> AnalyzeDomainAsync(ParsedEmail eml)
        {
            if (eml == null)
            {
                throw new ArgumentNullException(nameof(eml));
            }

            var domain = EmailDomainExtractor.ExtractDomain(eml);

            if (string.IsNullOrEmpty(domain))
            {
                return new DetectionResult
                {
                    EmailSubject = eml.Subject,
                    Percentage = 0,
                    Flags = ["No valid domain found!"],
                    DateOfScan = DateTime.Now
                };
            }

            try
            {
                var whoisResponse = await _whoisLookup.LookupAsync(domain);
                return AnalyzeWhoIsResponse(whoisResponse, domain, eml.Subject);
            }
            catch (Exception ex)
            {
                return new DetectionResult
                {
                    EmailSubject = eml.Subject,
                    Percentage = 0,
                    Flags = [$"WHOIS lookup failed: {ex.Message}"],
                    DateOfScan = DateTime.Now
                };
            }
        }

        private DetectionResult AnalyzeWhoIsResponse(WhoisResponse whoisResponse, string domain, string subject)
        {
            var flags = new List<string>();

            // Debug output
            Console.WriteLine($"Analyzing domain: {domain}");
            if (whoisResponse != null)
            {
                var response = System.Text.Json.JsonSerializer.Serialize(whoisResponse, new System.Text.Json.JsonSerializerOptions
                {
                    WriteIndented = true
                });
                Console.WriteLine("WHOIS Response:");
                Console.WriteLine(response);
            }

            if (whoisResponse == null)
            {
                flags.Add("No WHOIS response received");
            }
            else if (whoisResponse.Status == WhoisStatus.NotFound)
            {
                flags.Add($"Domain does not exist: {domain}");
                flags.Add("HIGH RISK: Non-existent domain - likely phishing");
            }
            else
            {
                // Domain exists - run all checks
                flags.Add("Domain exists in WHOIS database");

                // Run each analysis check
                AnalyzeDomainAge(whoisResponse, flags);
                AnalyzeRegistrar(whoisResponse, flags);
                AnalyzeWhoisPrivacy(whoisResponse, flags);
                AnalyzeDomainStatus(whoisResponse, flags);
                AnalyzeTLD(domain, flags);
                AnalyzeBrandImpersonation(domain, flags);
                AnalyzeNameServers(whoisResponse, flags);
                AnalyzeContactInformation(whoisResponse, flags);
            }

            return new DetectionResult
            {
                EmailSubject = subject,
                Percentage = 0,
                Flags = flags,
                DateOfScan = DateTime.Now
            };
        }

        private void AnalyzeDomainAge(WhoisResponse whoisResponse, List<string> flags)
        {
            if (!whoisResponse.Registered.HasValue)
            {
                flags.Add("Domain registration date unknown");
                return;
            }

            var domainAge = DateTime.Now - whoisResponse.Registered.Value;
            if (domainAge.TotalDays < 30)
            {
                flags.Add($"HIGH RISK: Domain is very new: {domainAge.TotalDays:F0} days old");
            }
            else if (domainAge.TotalDays < 365)
            {
                flags.Add($"MEDIUM RISK: Domain is less than a year old: {domainAge.TotalDays:F0} days old");
            }
            else
            {
                flags.Add("Domain is older than a year");
            }
        }

        private void AnalyzeRegistrar(WhoisResponse whoisResponse, List<string> flags)
        {
            if (string.IsNullOrEmpty(whoisResponse.Registrar?.Name))
            {
                flags.Add("Registrar information hidden or unavailable");
                return;
            }

            var registrar = whoisResponse.Registrar.Name.ToLower();
            var suspiciousRegistrars = new[] { "namecheap", "porkbun", "godaddy", "namesilo", "dynadot", "epik" };

            if (suspiciousRegistrars.Any(registrar.Contains))
            {
                flags.Add($"MEDIUM RISK: Uses common phishing registrar: {whoisResponse.Registrar.Name}");
            }
        }

        private void AnalyzeWhoisPrivacy(WhoisResponse whoisResponse, List<string> flags)
        {
            if (IsWhoisPrivacyEnabled(whoisResponse))
            {
                flags.Add("MEDIUM RISK: WHOIS privacy protection enabled");
            }
        }

        private void AnalyzeDomainStatus(WhoisResponse whoisResponse, List<string> flags)
        {
            if (whoisResponse.DomainStatus == null || !whoisResponse.DomainStatus.Any())
            {
                flags.Add("No domain status information available");
                return;
            }

            var statuses = whoisResponse.DomainStatus.Select(s => s.ToLower()).ToList();

            if (statuses.Any(s => s.Contains("clienthold") || s.Contains("serverhold")))
            {
                flags.Add("HIGH RISK: Domain has hold status - may be suspended");
            }

            if (statuses.Any(s => s.Contains("pendingdelete") || s.Contains("redemption")))
            {
                flags.Add("HIGH RISK: Domain in pending delete status");
            }

            if (statuses.Any(s => s.Contains("ok") || s.Contains("active")))
            {
                flags.Add("Domain status: Active");
            }
        }

        private void AnalyzeTLD(string domain, List<string> flags)
        {
            var domainParts = domain.Split('.');
            if (domainParts.Length <= 1) return;

            var tld = domainParts.Last().ToLower();
            var riskyTlds = new[] { "xyz", "top", "loan", "win", "club", "site", "online", "gq", "ml", "ga", "cf", "tk", "cyou", "pw", "cc" };
            var establishedTlds = new[] { "com", "org", "net", "edu", "gov" };

            if (riskyTlds.Contains(tld))
            {
                flags.Add($"MEDIUM RISK: Uses risky TLD: .{tld}");
            }
            else if (establishedTlds.Contains(tld))
            {
                flags.Add($"Uses established TLD: .{tld}");
            }
        }

        private void AnalyzeBrandImpersonation(string domain, List<string> flags)
        {
            var domainName = domain.Split('.')[0].ToLower();
            var commonBrands = new[] { "microsoft", "google", "apple", "amazon", "paypal", "netflix", "facebook", "instagram", "twitter" };

            foreach (var brand in commonBrands)
            {
                if (domainName.Contains(brand) && !domain.EndsWith($".{brand}.com"))
                {
                    flags.Add($"HIGH RISK: Possible brand impersonation: {brand}");
                    break;
                }
            }
        }

        private void AnalyzeNameServers(WhoisResponse whoisResponse, List<string> flags)
        {
            if (whoisResponse.NameServers?.Any() != true) return;

            var nameServers = whoisResponse.NameServers.Select(ns => ns.ToLower());
            var suspiciousNameServers = new[] { "cloudflare", "namecheap", "godaddy" };

            if (nameServers.Any(ns => suspiciousNameServers.Any(ns.Contains)))
            {
                flags.Add("MEDIUM RISK: Uses common suspicious name servers");
            }
        }

        private void AnalyzeContactInformation(WhoisResponse whoisResponse, List<string> flags)
        {
            var registrantEmail = whoisResponse.Registrant?.Email?.ToLower() ?? "";
            var adminEmail = whoisResponse.AdminContact?.Email?.ToLower() ?? "";
            var privacyEmails = new[] { "privacy", "whois", "contact@", "info@", "admin@" };

            if (privacyEmails.Any(pattern => registrantEmail.Contains(pattern) || adminEmail.Contains(pattern)))
            {
                flags.Add("MEDIUM RISK: Generic or privacy-protected contact email");
            }

            if (string.IsNullOrEmpty(whoisResponse.Registrant?.Organization))
            {
                flags.Add("No organization information provided");
            }
        }

        private bool IsWhoisPrivacyEnabled(WhoisResponse whoisResponse)
        {
            var privacyIndicators = new[] { "privacy", "redacted", "whois", "protected", "anonymized", "whoisguard", "identity protect" };

            var registrantName = whoisResponse.Registrant?.Name?.ToLower() ?? "";
            var registrantOrganization = whoisResponse.Registrant?.Organization?.ToLower() ?? "";

            return privacyIndicators.Any(indicator =>
                registrantName.Contains(indicator) ||
                registrantOrganization.Contains(indicator));
        }
    }
}