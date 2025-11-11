using PhishingDetectionEngine.Core.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace PhishingDetectionEngine.Core.Utilities
{
    public static class EmailDomainExtractor
    {
        private static readonly Regex EmailRegex = new Regex(
            @"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
            RegexOptions.Compiled);
        public static string ExtractDomain(ParsedEmail eml)
        {
            if (eml == null)
            {
                throw new ArgumentNullException(nameof(eml));
            }
            else
            {
                var sender = eml.From;
                if (string.IsNullOrEmpty(sender))
                {
                    return string.Empty;
                }
                else
                {
                    return ExtractDomainFromString(sender);
                } 
            }
        }

        private static string ExtractDomainFromString(string emailSender)
        {
            if (string.IsNullOrEmpty(emailSender))
            {
                return string.Empty; 
            }
            else
            {
                var emailMatch = EmailRegex.Match(emailSender);
                if (emailMatch.Success)
                {
                    string email = emailMatch.Value;
                    int atIndex = email.IndexOf('@');
                    if (atIndex > 0 && atIndex < email.Length - 1)
                    {
                        return email.Substring(atIndex + 1).ToLowerInvariant();
                    }
                }

                //fallback option if REGEX decides to fail.
                return ExtractDomainManually(emailSender);
            }
        }

        private static string ExtractDomainManually(string emailString)
        {
            string cleanedString = emailString.Trim();

            // Handle format: "Name <email@domain.com>"
            int angleBracketStart = cleanedString.IndexOf('<');
            int angleBracketEnd = cleanedString.LastIndexOf('>');

            if (angleBracketStart >= 0 && angleBracketEnd > angleBracketStart)
            {
                cleanedString = cleanedString.Substring(angleBracketStart + 1,
                    angleBracketEnd - angleBracketStart - 1);
            }

            // Remove any remaining angle brackets
            cleanedString = cleanedString.Trim().TrimStart('<').TrimEnd('>').Trim();

            // Find @ symbol and extract domain
            int atIndex = cleanedString.LastIndexOf('@');
            if (atIndex > 0 && atIndex < cleanedString.Length - 1)
            {
                string domain = cleanedString.Substring(atIndex + 1).Trim();
                if (!string.IsNullOrEmpty(domain))
                {
                    return domain.ToLowerInvariant();
                }
            }

            return string.Empty;
        }
    }
}
