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

            // Extract domain from email
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
                // Lookup domain in WHOIS database
                var whoisResponse = await _whoisLookup.LookupAsync(domain);
                return await AnalyzeWhoIsResponse(whoisResponse, domain, eml.Subject);
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

        private async Task<DetectionResult> AnalyzeWhoIsResponse(WhoisResponse whoisResponse, string domain, string subject)
        {
            var flags = new List<string>();
            var riskScore = 0;
            var maxRiskScore = 100;

            // Debug output for testing
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
                riskScore += 20;
            }
            else if (whoisResponse.Status == WhoisStatus.NotFound)
            {
                // Handle subdomains and non-existent domains
                riskScore += await HandlePossibleSubdomain(domain, flags);
            }
            else
            {
                // Domain exists - run all security checks
                flags.Add("Domain exists in WHOIS database");

                // Run all phishing detection checks and accumulate risk scores
                riskScore += AnalyzeDomainAge(whoisResponse, flags);
                riskScore += AnalyzeRegistrar(whoisResponse, flags);
                riskScore += AnalyzeWhoisPrivacy(whoisResponse, flags);
                riskScore += AnalyzeDomainStatus(whoisResponse, flags);
                riskScore += AnalyzeTLD(domain, flags);
                riskScore += AnalyzeBrandImpersonation(domain, flags);
                riskScore += AnalyzeNameServers(whoisResponse, flags);
                riskScore += AnalyzeContactInformation(whoisResponse, flags);
            }

            // Calculate percentage (0% = safe, 100% = high risk)
            var percentage = Math.Min(riskScore, maxRiskScore);

            return new DetectionResult
            {
                EmailSubject = subject,
                Percentage = percentage,
                Flags = flags,
                DateOfScan = DateTime.Now
            };
        }

        private async Task<int> HandlePossibleSubdomain(string domain, List<string> flags)
        {
            var riskScore = 0;

            // Extract root domain (e.g., eu.knowbe4.com -> knowbe4.com)
            var rootDomain = GetRootDomain(domain);

            // If same, it's truly non-existent
            if (rootDomain == domain)
            {
                flags.Add($"Domain does not exist: {domain}");
                flags.Add("HIGH RISK: Non-existent domain - likely phishing");
                riskScore += 80;
                return riskScore;
            }

            // It's a subdomain - check if root domain exists
            flags.Add($"Subdomain detected: {domain}");
            flags.Add($"Checking root domain: {rootDomain}");

            try
            {
                var rootWhoisResponse = await _whoisLookup.LookupAsync(rootDomain);

                if (rootWhoisResponse?.Status == WhoisStatus.Found)
                {
                    flags.Add($"Root domain exists: {rootDomain}");

                    // Analyze root domain for context
                    riskScore += AnalyzeDomainAge(rootWhoisResponse, flags);
                    riskScore += AnalyzeRegistrar(rootWhoisResponse, flags);
                    riskScore += AnalyzeWhoisPrivacy(rootWhoisResponse, flags);
                    riskScore += AnalyzeDomainStatus(rootWhoisResponse, flags);
                    riskScore += AnalyzeTLD(rootDomain, flags);
                    riskScore += AnalyzeBrandImpersonation(rootDomain, flags);

                    // Check if subdomain is suspicious
                    riskScore += await AnalyzeSubdomainRisk(domain, rootDomain, flags);
                }
                else
                {
                    flags.Add($"Root domain also does not exist: {rootDomain}");
                    flags.Add("HIGH RISK: Non-existent domain - likely phishing");
                    riskScore += 80;
                }
            }
            catch (Exception ex)
            {
                flags.Add($"Could not verify root domain: {ex.Message}");
                flags.Add("Assuming high risk due to verification failure");
                riskScore += 40;
            }

            return riskScore;
        }

        private async Task<int> AnalyzeSubdomainRisk(string subdomain, string rootDomain, List<string> flags)
        {
            var riskScore = 0;

            // Check if subdomain actually resolves in DNS
            var subdomainResolves = await ValidateDomainExists(subdomain);

            if (!subdomainResolves)
            {
                flags.Add("Subdomain does not resolve in DNS - suspicious");
                flags.Add("Could be non-existent or malicious subdomain");
                riskScore += 30;
                return riskScore;
            }

            flags.Add("Subdomain resolves in DNS");

            // Compare IP addresses - different IPs indicate potential compromise
            var ipComparison = await CompareIPAddresses(subdomain, rootDomain);

            if (ipComparison.IsDifferent)
            {
                flags.Add($"HIGH RISK: Subdomain uses different IP ({ipComparison.SubdomainIP}) than root domain ({ipComparison.RootDomainIP})");
                flags.Add("Possible compromised subdomain or phishing setup");
                riskScore += 50;
            }
            else
            {
                flags.Add("Subdomain uses same IP as root domain - likely legitimate");
                riskScore -= 10; // Positive indicator
            }

            // Check for suspicious subdomain names
            riskScore += AnalyzeSubdomainPatterns(subdomain, rootDomain, flags);

            return riskScore;
        }

        private async Task<bool> ValidateDomainExists(string domain)
        {
            try
            {
                // Try to resolve domain via DNS
                var hostEntry = await Dns.GetHostEntryAsync(domain);
                return hostEntry.AddressList.Length > 0;
            }
            catch (System.Net.Sockets.SocketException)
            {
                return false; // DNS resolution failed
            }
            catch
            {
                return false; // Other errors
            }
        }

        private async Task<(bool IsDifferent, string SubdomainIP, string RootDomainIP)> CompareIPAddresses(string subdomain, string rootDomain)
        {
            try
            {
                var subdomainEntry = await Dns.GetHostEntryAsync(subdomain);
                var rootDomainEntry = await Dns.GetHostEntryAsync(rootDomain);

                if (subdomainEntry.AddressList.Length == 0 || rootDomainEntry.AddressList.Length == 0)
                    return (true, "Unknown", "Unknown");

                var subdomainIP = subdomainEntry.AddressList[0].ToString();
                var rootDomainIP = rootDomainEntry.AddressList[0].ToString();

                return (subdomainIP != rootDomainIP, subdomainIP, rootDomainIP);
            }
            catch
            {
                return (true, "Unknown", "Unknown"); // Assume different if we can't check
            }
        }

        private int AnalyzeSubdomainPatterns(string fullDomain, string rootDomain, List<string> flags)
        {
            var riskScore = 0;
            var subdomainPart = fullDomain.Replace($".{rootDomain}", "").ToLower();

            // Check for suspicious subdomain names
            var highRiskPatterns = new[]
            {
                "login", "security", "verify", "account", "update",
                "secure", "auth", "signin", "password", "confirm"
            };

            if (highRiskPatterns.Any(pattern => subdomainPart.Contains(pattern)))
            {
                flags.Add($"HIGH RISK: Suspicious subdomain pattern: {subdomainPart}");
                riskScore += 40;
            }

            return riskScore;
        }

        private string GetRootDomain(string domain)
        {
            var parts = domain.Split('.');

            // Handle multi-part TLDs like co.uk, com.au
            if (parts.Length >= 3)
            {
                var potentialTld = $"{parts[^2]}.{parts[^1]}";

                if (IsLikelyMultiPartTld(potentialTld))
                {
                    if (parts.Length >= 4)
                        return $"{parts[^3]}.{parts[^2]}.{parts[^1]}";
                }

                // Standard case: take last two parts
                return $"{parts[^2]}.{parts[^1]}";
            }

            return domain;
        }

        private bool IsLikelyMultiPartTld(string potentialTld)
        {
            var parts = potentialTld.Split('.');
            if (parts.Length != 2) return false;

            var firstPart = parts[0];
            var secondPart = parts[1];

            var commonPrefixes = new[] { "co", "com", "net", "org", "ac", "edu", "gov" };
            var countryCodes = new[] { "uk", "au", "nz", "jp", "br", "in", "sg" };

            return commonPrefixes.Contains(firstPart) && countryCodes.Contains(secondPart);
        }

        // Check if domain is very new (common in phishing)
        private int AnalyzeDomainAge(WhoisResponse whoisResponse, List<string> flags)
        {
            var riskScore = 0;

            if (!whoisResponse.Registered.HasValue)
            {
                flags.Add("Domain registration date unknown");
                riskScore += 10;
                return riskScore;
            }

            var domainAge = DateTime.Now - whoisResponse.Registered.Value;
            if (domainAge.TotalDays < 30)
            {
                flags.Add($"HIGH RISK: Domain is very new: {domainAge.TotalDays:F0} days old");
                riskScore += 60;
            }
            else if (domainAge.TotalDays < 365)
            {
                flags.Add($"MEDIUM RISK: Domain is less than a year old: {domainAge.TotalDays:F0} days old");
                riskScore += 30;
            }
            else
            {
                flags.Add("Domain is older than a year");
                riskScore -= 10; // Positive indicator
            }

            return riskScore;
        }

        // Check if registrar is commonly used for phishing
        private int AnalyzeRegistrar(WhoisResponse whoisResponse, List<string> flags)
        {
            var riskScore = 0;

            if (string.IsNullOrEmpty(whoisResponse.Registrar?.Name))
            {
                flags.Add("Registrar information hidden or unavailable");
                riskScore += 15;
                return riskScore;
            }

            var registrar = whoisResponse.Registrar.Name.ToLower();

            // Score registrar based on risk characteristics
            var registrarRisk = CalculateRegistrarRisk(registrar);
            riskScore += registrarRisk;

            if (registrarRisk > 6)
            {
                flags.Add($"HIGH RISK: Suspicious registrar characteristics: {whoisResponse.Registrar.Name}");
            }
            else if (registrarRisk > 3)
            {
                flags.Add($"MEDIUM RISK: Questionable registrar: {whoisResponse.Registrar.Name}");
            }

            return riskScore;
        }

        private int CalculateRegistrarRisk(string registrar)
        {
            int score = 0;

            // Cheap/free registrars often used for phishing
            if (registrar.Contains("cheap") || registrar.Contains("free")) score += 3;

            // New/unknown registrars
            if (registrar.Length < 5) score += 2;

            // Privacy-focused registrars
            if (registrar.Contains("privacy") || registrar.Contains("anonymous")) score += 2;

            return score;
        }

        // Check if WHOIS privacy is enabled (hides owner identity)
        private int AnalyzeWhoisPrivacy(WhoisResponse whoisResponse, List<string> flags)
        {
            var riskScore = 0;

            if (IsWhoisPrivacyEnabled(whoisResponse))
            {
                flags.Add("MEDIUM RISK: WHOIS privacy protection enabled");
                riskScore += 25;
            }

            return riskScore;
        }

        // Check domain status (suspended, pending delete, etc.)
        private int AnalyzeDomainStatus(WhoisResponse whoisResponse, List<string> flags)
        {
            var riskScore = 0;

            if (whoisResponse.DomainStatus == null || !whoisResponse.DomainStatus.Any())
            {
                flags.Add("No domain status information available");
                riskScore += 10;
                return riskScore;
            }

            var statuses = whoisResponse.DomainStatus.Select(s => s.ToLower()).ToList();

            if (statuses.Any(s => s.Contains("clienthold") || s.Contains("serverhold")))
            {
                flags.Add("HIGH RISK: Domain has hold status - may be suspended");
                riskScore += 50;
            }

            if (statuses.Any(s => s.Contains("pendingdelete") || s.Contains("redemption")))
            {
                flags.Add("HIGH RISK: Domain in pending delete status");
                riskScore += 70;
            }

            if (statuses.Any(s => s.Contains("ok") || s.Contains("active")))
            {
                flags.Add("Domain status: Active");
                riskScore -= 5; // Positive indicator
            }

            return riskScore;
        }

        // Check if TLD is risky (new, uncommon, numeric)
        private int AnalyzeTLD(string domain, List<string> flags)
        {
            var riskScore = 0;
            var domainParts = domain.Split('.');
            if (domainParts.Length <= 1) return riskScore;

            var tld = domainParts.Last().ToLower();

            var tldRisk = CalculateTldRisk(tld);
            riskScore += tldRisk;

            if (tldRisk > 7)
                flags.Add($"HIGH RISK: Suspicious TLD characteristics: .{tld}");
            else if (tldRisk > 4)
                flags.Add($"MEDIUM RISK: Questionable TLD: .{tld}");

            return riskScore;
        }

        private int CalculateTldRisk(string tld)
        {
            int score = 0;

            // New TLDs are riskier
            if (tld.Length >= 4) score += 3;

            // Uncommon TLDs are riskier
            if (!IsCommonTld(tld)) score += 3;

            // Numeric TLDs are riskier
            if (tld.Any(char.IsDigit)) score += 2;

            return score;
        }

        private bool IsCommonTld(string tld)
        {
            var commonTlds = new[] { "com", "org", "net", "edu", "gov", "mil", "int" };
            return commonTlds.Contains(tld) || tld.Length <= 3;
        }

        // Check for fake brand domains
        private int AnalyzeBrandImpersonation(string domain, List<string> flags)
        {
            var riskScore = 0;
            var domainName = domain.Split('.')[0].ToLower();

            // Check for domains that look like "something-" pattern
            if (domainName.Contains('-') && domainName.Split('-').Length >= 2)
            {
                flags.Add($"MEDIUM RISK: Multi-part domain name - possible impersonation: {domainName}");
                riskScore += 20;
            }

            return riskScore;
        }

        // Check if name servers are suspicious
        private int AnalyzeNameServers(WhoisResponse whoisResponse, List<string> flags)
        {
            var riskScore = 0;

            if (whoisResponse.NameServers?.Any() != true)
            {
                flags.Add("No name server information available");
                riskScore += 10;
                return riskScore;
            }

            var nameServers = whoisResponse.NameServers.Select(ns => ns.ToLower());

            var nameServerRisk = CalculateNameServerRisk(nameServers);
            riskScore += nameServerRisk;

            if (nameServerRisk > 5)
                flags.Add("HIGH RISK: Suspicious name server characteristics");
            else if (nameServerRisk > 2)
                flags.Add("MEDIUM RISK: Questionable name servers");

            return riskScore;
        }

        private int CalculateNameServerRisk(IEnumerable<string> nameServers)
        {
            int score = 0;

            // Free/cheap hosting providers
            if (nameServers.Any(ns => ns.Contains("free") || ns.Contains("cheap"))) score += 3;

            // New/uncommon providers
            if (nameServers.Any(ns => ns.Length < 6)) score += 2;

            // Multiple different providers
            var uniqueProviders = nameServers.Select(ns => ns.Split('.')[^2]).Distinct().Count();
            if (uniqueProviders > 3) score += 2;

            return score;
        }

        // Check if contact information is hidden or generic
        private int AnalyzeContactInformation(WhoisResponse whoisResponse, List<string> flags)
        {
            var riskScore = 0;

            var registrantEmail = whoisResponse.Registrant?.Email?.ToLower() ?? "";
            var adminEmail = whoisResponse.AdminContact?.Email?.ToLower() ?? "";

            if (IsGenericContactEmail(registrantEmail) || IsGenericContactEmail(adminEmail))
            {
                flags.Add("MEDIUM RISK: Generic or privacy-protected contact email");
                riskScore += 20;
            }

            if (string.IsNullOrEmpty(whoisResponse.Registrant?.Organization))
            {
                flags.Add("No organization information provided");
                riskScore += 15;
            }

            return riskScore;
        }

        private bool IsGenericContactEmail(string email)
        {
            if (string.IsNullOrEmpty(email)) return false;

            var genericPatterns = new[] { "@", "contact", "info", "admin", "privacy", "whois" };
            return genericPatterns.Count(pattern => email.Contains(pattern)) >= 2;
        }

        // Check if WHOIS privacy is enabled
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