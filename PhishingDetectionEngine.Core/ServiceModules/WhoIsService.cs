using PhishingDetectionEngine.Core.Interfaces;
using PhishingDetectionEngine.Core.Models;
using PhishingDetectionEngine.Core.Utilities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
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
            else
            {
                var domain = EmailDomainExtractor.ExtractDomain(eml);

                if (domain == string.Empty)
                {
                    return new DetectionResult
                    {
                        EmailSubject = eml.Subject,
                        Percentage = 0,
                        Flags = ["No valid domain found!"],
                        DateOfScan = DateTime.Now
                    };
                }
                else
                {
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
            }
        }

        private DetectionResult AnalyzeWhoIsResponse(WhoisResponse whoisResponse, string domain, string subject)
        {
            var flags = new List<string>();
            int percentage = 0;

            if (whoisResponse != null)
            {
                // 1. Domain Registration Status
                if (whoisResponse.Registered.HasValue)
                {
                    var domainAge = DateTime.Now - whoisResponse.Registered.Value;
                    if (domainAge.TotalDays < 365)
                    {
                        flags.Add($"Domain is very new: {domainAge.TotalDays:F0} days old");
                    }
                    else
                    {
                        flags.Add("Domain appears older than a year old");
                    }
                }
                else
                {
                    flags.Add("Domain registration date unknown");
                }

                // 2. Domain Expiration
                if (whoisResponse.Expiration.HasValue)
                {
                    var daysUntilExpiry = (whoisResponse.Expiration.Value - DateTime.Now).TotalDays;
                    if (daysUntilExpiry < 30)
                    {
                        flags.Add($"Domain expires soon: {daysUntilExpiry:F0} days");
                    }
                }

                // 3. Registrar Analysis
                if (!string.IsNullOrEmpty(whoisResponse.Registrar?.Name))
                {
                    var registrar = whoisResponse.Registrar.Name.ToLower();

                    // Check for known suspicious registrars
                    var suspiciousRegistrars = new[] { "namecheap", "godaddy", "porkbun" };
                    if (suspiciousRegistrars.Any(r => registrar.Contains(r)))
                    {
                        flags.Add($"Uses common phishing registrar: {whoisResponse.Registrar.Name}");
                    }
                }
                else
                {
                    flags.Add("Registrar information hidden or unavailable");
                }

                // 4. Name Server Analysis
                if (whoisResponse.NameServers != null && whoisResponse.NameServers.Any())
                {
                    var nameServers = whoisResponse.NameServers.Select(ns => ns.ToLower()).ToList();

                    // Check for free/cheap hosting name servers
                    var suspiciousNameServers = new[] { "cloudflare", "namecheap", "bluehost" }; // Add more
                    if (nameServers.Any(ns => suspiciousNameServers.Any(sns => ns.Contains(sns))))
                    {
                        flags.Add("Uses common suspicious name servers");
                    }
                }

                // 5. Contact Information Analysis
                AnalyzeContactInformation(whoisResponse, flags);

                // 6. WHOIS Privacy Protection
                if (IsWhoisPrivacyEnabled(whoisResponse))
                {
                    flags.Add("WHOIS privacy protection enabled");
                }

                // 7. Domain Status Checks
                AnalyzeDomainStatus(whoisResponse, flags);

                // 8. Administrative Contact
                if (string.IsNullOrEmpty(whoisResponse.AdminContact?.Email))
                {
                    flags.Add("No admin contact email available");
                }
            }
            else
            {
                flags.Add("No WHOIS response received");
            }

            return new DetectionResult
            {
                EmailSubject = subject,
                Percentage = 0,
                Flags = flags,
                DateOfScan = DateTime.Now
            };
        }
    
        private void AnalyzeContactInformation(WhoisResponse whoisResponse, List<string> flags)
        {
            // Check if contact information is hidden or generic
            var registrantEmail = whoisResponse.Registrant?.Email?.ToLower() ?? "";
            var adminEmail = whoisResponse.AdminContact?.Email?.ToLower() ?? "";

            // Common privacy protection email patterns
            var privacyEmails = new[] { "privacy", "whois", "contact@", "info@", "admin@" };

            if (privacyEmails.Any(pattern => registrantEmail.Contains(pattern) || adminEmail.Contains(pattern)))
            {
                flags.Add("Generic or privacy-protected contact email");
            }

            // Check for mismatched contact information
            if (!string.IsNullOrEmpty(registrantEmail) && !string.IsNullOrEmpty(adminEmail) &&
                registrantEmail != adminEmail)
            {
                flags.Add("Registrant and admin contact emails differ");
            }
        }

        private bool IsWhoisPrivacyEnabled(WhoisResponse whoisResponse)
        {
            // Check common indicators of WHOIS privacy
            var privacyIndicators = new[]
            {
        "privacy", "redacted", "whois", "data protected",
        "contact privacy", "domain admin"
        };

            var registrantName = whoisResponse.Registrant?.Name?.ToLower() ?? "";
            var registrantOrganization = whoisResponse.Registrant?.Organization?.ToLower() ?? "";

            return privacyIndicators.Any(indicator =>
                registrantName.Contains(indicator) ||
                registrantOrganization.Contains(indicator));
        }

        private void AnalyzeDomainStatus(WhoisResponse whoisResponse, List<string> flags)
        {
            if (whoisResponse.DomainStatus != null && whoisResponse.DomainStatus.Any())
            {
                var statuses = whoisResponse.DomainStatus.Select(s => s.ToLower()).ToList();

                // Check for suspicious statuses
                if (statuses.Any(s => s.Contains("clienthold") || s.Contains("serverhold")))
                {
                    flags.Add("Domain has hold status - may be suspended");
                }

                if (statuses.Any(s => s.Contains("pendingdelete") || s.Contains("redemption")))
                {
                    flags.Add("Domain in pending delete or redemption status");
                }
            }
        }
    }
}
