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
            if(eml == null)
            {
                throw new ArgumentNullException(nameof(eml));
            }
            else
            {
                var domain = EmailDomainExtractor.ExtractDomain(eml);

                if(domain == string.Empty)
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

                        return AnalyzeWhoIsResponse(whoisResponse, domain);
                    }
                    catch(Exception ex)
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

        private DetectionResult AnalyzeWhoIsResponse(WhoisResponse whoisResponse, string domain)
        {
            var flags = new List<string>();
            int percentage = 0;

            if(whoisResponse != null)
            {
                if(whoisResponse.Registered.HasValue)
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
            }
        }
    }
}
