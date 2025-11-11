using PhishingDetectionEngine.Core.Interfaces;
using PhishingDetectionEngine.Core.Models;
using PhishingDetectionEngine.Core.Utilities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
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
                else
                {
                    try
                    {
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
            }
        }

        private async Task<DetectionResult> AnalyzeWhoIsResponse(WhoisResponse whoisResponse, string domain, string subject)
        {
            var flags = new List<string>();

            if (whoisResponse == null)
            {
                flags.Add("No WHOIS response received");
            }
            else if (whoisResponse.Status == WhoisStatus.NotFound)
            {
                // Handle subdomain scenarios
                await HandleNotFoundDomain(domain, flags);
            }
            else
            {
                // Domain exists - run full analysis
                AnalyzeExistingDomain(whoisResponse, domain, flags);
            }

            return CreateResult(subject, flags);
        }

        private async Task HandleNotFoundDomain(string domain, List<string> flags)
        {
            var rootDomain = GetRootDomain(domain);

            if (rootDomain != domain)
            {
                // It's a subdomain - analyze both levels
                await AnalyzeSubdomainScenario(domain, rootDomain, flags);
            }
            else
            {
                // Truly non-existent domain
                flags.Add($"Domain does not exist: {domain}");
                flags.Add("High probability of phishing using non-existent domain");
                AnalyzeDomainPatterns(domain, flags); // Check for suspicious patterns anyway
            }
        }

        private async Task AnalyzeSubdomainScenario(string fullDomain, string rootDomain, List<string> flags)
        {
            flags.Add($"Subdomain detected: {fullDomain}");

            // 1. Check if root domain exists
            WhoisResponse rootWhoisResponse = null;
            try
            {
                rootWhoisResponse = await _whoisLookup.LookupAsync(rootDomain);
            }
            catch (Exception ex)
            {
                flags.Add($"Could not verify root domain {rootDomain}: {ex.Message}");
            }

            // 2. Check if subdomain resolves in DNS
            var subdomainResolves = await ValidateSubdomainExists(fullDomain);

            // 3. Analyze the scenario
            if (rootWhoisResponse?.Status == WhoisStatus.Found)
            {
                flags.Add($"Root domain exists: {rootDomain}");
                AnalyzeRootDomainCharacteristics(rootWhoisResponse, flags);

                // ✅ FIX: Run FULL WHOIS analysis on the root domain
                AnalyzeExistingDomain(rootWhoisResponse, rootDomain, flags);

                if (subdomainResolves)
                {
                    flags.Add("Subdomain resolves in DNS - likely legitimate");
                }
                else
                {
                    flags.Add("Subdomain does not resolve in DNS - suspicious");
                    flags.Add("Could be DNS spoofing or non-existent subdomain");
                }
            }
            else
            {
                // Root domain also doesn't exist or couldn't be checked
                flags.Add($"Root domain {rootDomain} also appears invalid");
                flags.Add("Very high probability of phishing");

                if (subdomainResolves)
                {
                    flags.Add("Suspicious: Domain doesn't exist but DNS resolves - possible cache poisoning");
                }
            }

            // 4. Always analyze patterns regardless of existence
            AnalyzeDomainPatterns(fullDomain, flags);
            AnalyzeSubdomainPatterns(fullDomain, flags);
        }

        private void AnalyzeExistingDomain(WhoisResponse whoisResponse, string domain, List<string> flags)
        {
            flags.Add("Domain exists in WHOIS database");

            Console.WriteLine(domain);
            var response = System.Text.Json.JsonSerializer.Serialize(whoisResponse, new System.Text.Json.JsonSerializerOptions
            {
                WriteIndented = true
            });
            Console.WriteLine(response);
            // Run all your existing analysis
            AnalyzeDomainAge(whoisResponse, flags);
            AnalyzeExpiration(whoisResponse, flags);
            AnalyzeRegistrar(whoisResponse, flags);
            AnalyzeNameServers(whoisResponse, flags);
            AnalyzeContactInformation(whoisResponse, flags);
            AnalyzeTLD(domain, flags);
            AnalyzeDomainPatterns(domain, flags);

            if (IsWhoisPrivacyEnabled(whoisResponse))
            {
                flags.Add("WHOIS privacy protection enabled");
            }

            AnalyzeDomainStatus(whoisResponse, flags);
            AnalyzeAdminContact(whoisResponse, flags);

            // Additional check for subdomains of existing domains
            if (domain.Contains('.') && domain.Split('.').Length > 2)
            {
                AnalyzeSubdomainPatterns(domain, flags);
            }
        }

        private void AnalyzeRootDomainCharacteristics(WhoisResponse rootWhoisResponse, List<string> flags)
        {
            // Analyze the root domain for legitimacy indicators
            if (rootWhoisResponse.Registered.HasValue)
            {
                var rootDomainAge = DateTime.Now - rootWhoisResponse.Registered.Value;
                if (rootDomainAge.TotalDays > 365)
                {
                    flags.Add($"Root domain is established ({rootDomainAge.TotalDays:F0} days old)");
                }
                else if (rootDomainAge.TotalDays < 30)
                {
                    flags.Add($"Root domain is very new ({rootDomainAge.TotalDays:F0} days old)");
                }
            }

            if (!string.IsNullOrEmpty(rootWhoisResponse.Registrar?.Name))
            {
                var registrar = rootWhoisResponse.Registrar.Name.ToLower();
                var reputableRegistrars = new[] { "markmonitor", "csc", "corporation service", "cloudflare" };

                if (reputableRegistrars.Any(registrar.Contains))
                {
                    flags.Add("Root domain uses reputable corporate registrar");
                }
            }
        }

        private async Task<bool> ValidateSubdomainExists(string domain)
        {
            try
            {
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

        private string GetRootDomain(string domain)
        {
            var parts = domain.Split('.');
            if (parts.Length >= 3)
            {
                // For domains like feedback.hilton.com -> hilton.com
                // For sub.sub.domain.com -> domain.com
                return $"{parts[^2]}.{parts[^1]}";
            }
            return domain;
        }

        private void AnalyzeSubdomainPatterns(string domain, List<string> flags)
        {
            var rootDomain = GetRootDomain(domain);
            var subdomainPart = domain.Replace($".{rootDomain}", "").ToLower();

            // High-confidence legitimate patterns
            var commonLegitimatePatterns = new[]
            {
                "www", "mail", "email", "smtp", "imap", "pop", "ftp",
                "api", "cdn", "static", "assets", "img", "images",
                "blog", "news", "info", "support", "help", "contact",
                "careers", "jobs", "about", "team", "status", "uptime",
                "feedback", "newsletter", "media", "download", "docs"
            };

            // High-risk suspicious patterns
            var highRiskPatterns = new[]
            {
                "login", "security", "verify", "account", "update",
                "secure", "auth", "signin", "password", "confirm",
                "validation", "activation", "recovery", "reset",
                "admin", "portal", "office365", "sharepoint", "microsoft",
                "paypal", "banking", "financial", "irs", "tax"
            };

            // Medium-risk patterns
            var mediumRiskPatterns = new[]
            {
                "service", "services", "client", "customers", "user",
                "members", "portal", "dashboard", "myaccount", "profile",
                "billing", "invoice", "payment", "securelogin"
            };

            if (highRiskPatterns.Any(pattern =>
                subdomainPart.Equals(pattern) ||
                subdomainPart.StartsWith(pattern + "-") ||
                subdomainPart.EndsWith("-" + pattern) ||
                subdomainPart.Contains("-" + pattern + "-")))
            {
                flags.Add($"HIGH RISK: Suspicious subdomain pattern '{subdomainPart}'");
            }
            else if (mediumRiskPatterns.Any(pattern =>
                subdomainPart.Equals(pattern) ||
                subdomainPart.StartsWith(pattern + "-") ||
                subdomainPart.EndsWith("-" + pattern)))
            {
                flags.Add($"MEDIUM RISK: Questionable subdomain pattern '{subdomainPart}'");
            }
            else if (commonLegitimatePatterns.Any(pattern =>
                subdomainPart.Equals(pattern)))
            {
                flags.Add($"LOW RISK: Common legitimate subdomain pattern '{subdomainPart}'");
            }

            // Check for random-looking subdomains
            if (IsRandomDomain(subdomainPart))
            {
                flags.Add("Subdomain appears to use random characters");
            }

            // Check for excessive length
            if (subdomainPart.Length > 30)
            {
                flags.Add("Subdomain is unusually long");
            }

            // Check for multiple subdomain levels
            var subdomainLevels = subdomainPart.Split('.').Length;
            if (subdomainLevels > 2)
            {
                flags.Add($"Multiple subdomain levels detected ({subdomainLevels})");
            }
        }

        // Your existing methods remain the same (just copied for completeness)
        private void AnalyzeDomainAge(WhoisResponse whoisResponse, List<string> flags)
        {
            if (!whoisResponse.Registered.HasValue)
            {
                flags.Add("Domain registration date unknown");
            }
            else
            {
                var domainAge = DateTime.Now - whoisResponse.Registered.Value;
                if (domainAge.TotalDays < 30)
                {
                    flags.Add($"Domain is very new (less than 30 days): {domainAge.TotalDays:F0} days old");
                }
                else if (domainAge.TotalDays < 365)
                {
                    flags.Add($"Domain is relatively new: {domainAge.TotalDays:F0} days old");
                }
                else
                {
                    flags.Add("Domain appears older than a year old");
                }
            }
        }

        private void AnalyzeExpiration(WhoisResponse whoisResponse, List<string> flags)
        {
            if (whoisResponse.Expiration.HasValue)
            {
                var daysUntilExpiry = (whoisResponse.Expiration.Value - DateTime.Now).TotalDays;
                if (daysUntilExpiry < 7)
                {
                    flags.Add($"Domain expires very soon: {daysUntilExpiry:F0} days");
                }
                else if (daysUntilExpiry < 30)
                {
                    flags.Add($"Domain expires soon: {daysUntilExpiry:F0} days");
                }
            }
        }

        private void AnalyzeRegistrar(WhoisResponse whoisResponse, List<string> flags)
        {
            if (string.IsNullOrEmpty(whoisResponse.Registrar?.Name))
            {
                flags.Add("Registrar information hidden or unavailable");
            }
            else
            {
                var registrar = whoisResponse.Registrar.Name.ToLower();

                var highRiskRegistrars = new[]
                {
                    "namecheap", "porkbun", "name.com", "dynadot",
                    "internet.bs", "namesilo", "epik", "gandi",
                    "register.com", "tucows", "enom", "resellerclub",
                    "godaddy"
                };

                var budgetRegistrars = new[]
                {
                    "freenom", "dot.tk", "get.africa", "register.bar",
                    "biz.cn", "cnobin"
                };

                if (highRiskRegistrars.Any(registrar.Contains))
                {
                    flags.Add($"Uses common phishing registrar: {whoisResponse.Registrar.Name}");
                }

                if (budgetRegistrars.Any(registrar.Contains))
                {
                    flags.Add($"Uses budget/free registrar often abused: {whoisResponse.Registrar.Name}");
                }
            }
        }

        private void AnalyzeNameServers(WhoisResponse whoisResponse, List<string> flags)
        {
            if (whoisResponse.NameServers?.Any() != true)
            {
                flags.Add("No name server information available");
            }
            else
            {
                var suspiciousNameServers = new[]
                {
                    "cloudflare", "namecheap", "bluehost", "hostinger",
                    "godaddy", "siteground", "dreamhost", "hostgator"
                };

                var reputableNameServers = new[]
                {
                    "amazonaws", "azure", "google", "akamai",
                    "fastly", "cloudfront"
                };

                var nameServers = whoisResponse.NameServers.Select(ns => ns.ToLower());

                if (nameServers.Any(ns => suspiciousNameServers.Any(ns.Contains)))
                {
                    flags.Add("Uses common suspicious name servers");
                }

                if (nameServers.Any(ns => reputableNameServers.Any(ns.Contains)))
                {
                    flags.Add("Uses reputable cloud infrastructure");
                }
            }
        }

        private void AnalyzeContactInformation(WhoisResponse whoisResponse, List<string> flags)
        {
            var registrantEmail = whoisResponse.Registrant?.Email?.ToLower() ?? "";
            var adminEmail = whoisResponse.AdminContact?.Email?.ToLower() ?? "";

            var privacyEmails = new[]
            {
                "privacy", "whois", "contact@", "info@", "admin@",
                "placeholder", "example", "domainadmin", "registrant"
            };

            if (privacyEmails.Any(pattern => registrantEmail.Contains(pattern) || adminEmail.Contains(pattern)))
            {
                flags.Add("Generic or privacy-protected contact email");
            }

            if (!string.IsNullOrEmpty(registrantEmail) && !string.IsNullOrEmpty(adminEmail))
            {
                if (registrantEmail != adminEmail)
                {
                    flags.Add("Registrant and admin contact emails differ");
                }
            }

            if (string.IsNullOrEmpty(whoisResponse.Registrant?.Organization))
            {
                flags.Add("No organization information provided");
            }
        }

        private void AnalyzeTLD(string domain, List<string> flags)
        {
            var domainParts = domain.Split('.');
            if (domainParts.Length > 1)
            {
                var tld = domainParts.Last().ToLower();

                var highRiskTlds = new[]
                {
                    "xyz", "top", "loan", "win", "club", "site", "online",
                    "click", "link", "stream", "download", "gq", "ml", "ga", "cf", "tk"
                };

                var newRiskyTlds = new[]
                {
                    "cyou", "rest", "mom", "work", "biz", "info", "pw", "cc"
                };

                var reputableTlds = new[]
                {
                    "com", "org", "net", "edu", "gov", "mil"
                };

                if (highRiskTlds.Contains(tld))
                {
                    flags.Add($"Uses high-risk TLD: .{tld}");
                }
                else if (newRiskyTlds.Contains(tld))
                {
                    flags.Add($"Uses new/obscure TLD: .{tld}");
                }
                else if (reputableTlds.Contains(tld))
                {
                    flags.Add($"Uses established TLD: .{tld}");
                }
            }
        }

        private void AnalyzeDomainPatterns(string domain, List<string> flags)
        {
            var domainName = domain.Split('.')[0].ToLower();

            var suspiciousPrefixes = new[]
            {
                "login-", "security-", "verify-", "account-", "update-",
                "secure-", "service-", "support-", "admin-", "mail-",
                "auth-", "signin-", "password-", "confirm-"
            };

            var suspiciousSuffixes = new[]
            {
                "-login", "-security", "-verify", "-account", "-update",
                "-secure", "-service", "-support", "-admin"
            };

            var commonBrands = new[]
            {
                "microsoft", "google", "apple", "amazon", "paypal",
                "netflix", "facebook", "instagram", "twitter", "linkedin",
                "bankofamerica", "wellsfargo", "chase", "citibank"
            };

            foreach (var prefix in suspiciousPrefixes)
            {
                if (domainName.StartsWith(prefix))
                {
                    flags.Add($"Domain uses suspicious prefix: '{prefix}'");
                    break;
                }
            }

            foreach (var suffix in suspiciousSuffixes)
            {
                if (domainName.EndsWith(suffix))
                {
                    flags.Add($"Domain uses suspicious suffix: '{suffix}'");
                    break;
                }
            }

            foreach (var brand in commonBrands)
            {
                if (domainName.Contains(brand))
                {
                    if (!domain.EndsWith($".{brand}.com"))
                    {
                        flags.Add($"Possible brand impersonation: {brand}");
                    }
                    break;
                }
            }

            if (IsRandomDomain(domainName))
            {
                flags.Add("Domain appears to use random characters");
            }

            var hyphenCount = domainName.Count(c => c == '-');
            if (hyphenCount >= 3)
            {
                flags.Add($"Domain has excessive hyphens: {hyphenCount}");
            }

            var digitCount = domainName.Count(char.IsDigit);
            if (digitCount >= 3)
            {
                flags.Add($"Domain has excessive numbers: {digitCount}");
            }
        }

        private bool IsRandomDomain(string domainName)
        {
            if (domainName.Length >= 10)
            {
                var consonantCount = domainName.Count(c => "bcdfghjklmnpqrstvwxyz".Contains(char.ToLower(c)));
                var vowelCount = domainName.Count(c => "aeiou".Contains(char.ToLower(c)));

                if ((consonantCount > vowelCount * 2.5) || (vowelCount > consonantCount * 2.5))
                {
                    return true;
                }
                else
                {
                    return false;
                }
            }
            else
            {
                return false;
            }
        }

        private bool IsWhoisPrivacyEnabled(WhoisResponse whoisResponse)
        {
            var privacyIndicators = new[]
            {
                "privacy", "redacted", "whois", "data protected",
                "contact privacy", "domain admin", "protected", "anonymized",
                "whoisguard", "identity protect", "privacy service"
            };

            var registrantName = whoisResponse.Registrant?.Name?.ToLower() ?? "";
            var registrantOrganization = whoisResponse.Registrant?.Organization?.ToLower() ?? "";

            if (privacyIndicators.Any(indicator =>
                registrantName.Contains(indicator) ||
                registrantOrganization.Contains(indicator)))
            {
                return true;
            }
            else
            {
                return false;
            }
        }

        private void AnalyzeDomainStatus(WhoisResponse whoisResponse, List<string> flags)
        {
            if (whoisResponse.DomainStatus != null && whoisResponse.DomainStatus.Any())
            {
                var statuses = whoisResponse.DomainStatus.Select(s => s.ToLower()).ToList();

                if (statuses.Any(s => s.Contains("clienthold") || s.Contains("serverhold")))
                {
                    flags.Add("Domain has hold status - may be suspended");
                }

                if (statuses.Any(s => s.Contains("pendingdelete") || s.Contains("redemption")))
                {
                    flags.Add("Domain in pending delete or redemption status");
                }

                if (statuses.Any(s => s.Contains("inactive")))
                {
                    flags.Add("Domain status: Inactive");
                }

                if (statuses.Any(s => s.Contains("transferprohibited")))
                {
                    flags.Add("Domain transfers locked - may be compromised");
                }

                if (statuses.Any(s => s.Contains("ok") || s.Contains("active")))
                {
                    flags.Add("Domain status: Active");
                }
            }
            else
            {
                flags.Add("No domain status information available");
            }
        }

        private void AnalyzeAdminContact(WhoisResponse whoisResponse, List<string> flags)
        {
            if (string.IsNullOrEmpty(whoisResponse.AdminContact?.Email))
            {
                flags.Add("No admin contact email available");
            }

            if (string.IsNullOrEmpty(whoisResponse.TechnicalContact?.Email))
            {
                flags.Add("No technical contact email available");
            }
        }

        private DetectionResult CreateResult(string subject, List<string> flags)
        {
            return new DetectionResult
            {
                EmailSubject = subject,
                Percentage = 0,
                Flags = flags,
                DateOfScan = DateTime.Now
            };
        }
    }
}