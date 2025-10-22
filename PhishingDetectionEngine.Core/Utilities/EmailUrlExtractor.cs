// EmailUrlExtractor.cs
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using PhishingDetectionEngine.Core.Models;

namespace PhishingDetectionEngine.Core.Utilities
{
    public static class EmailUrlExtractor
    {
        private static readonly Regex UrlRegex = new Regex(
            @"https?://[^\s/$.?#].[^\s""'<>\)\]\[{}|\\^`]*",
            RegexOptions.IgnoreCase | RegexOptions.Compiled  // Case insensitive and compiled for performance
        );
        public static List<string> ExtractUrls(ParsedEmail email)
        {
            // Return empty list if email is null
            if (email == null) return new List<string>();

            var urls = new List<string>();

            // Extract URLs from all relevant email content fields
            ExtractFromText(email.Subject, urls);
            ExtractFromText(email.TextBody, urls);
            ExtractFromText(email.HtmlBody, urls);

            // Process URLs: normalize, filter out empty ones, and remove duplicates
            return urls.Select(NormalizeUrl)
                      .Where(url => !string.IsNullOrEmpty(url))  // Remove any null or empty URLs
                      .Distinct()  // Remove duplicate URLs
                      .ToList();
        }
        // Extracts URLs from a text string and adds them to the collection
        private static void ExtractFromText(string text, List<string> urls)
        {
            // Skip if text is null, empty, or just whitespace
            if (string.IsNullOrWhiteSpace(text)) return;

            // Find all URL matches in the text
            foreach (Match match in UrlRegex.Matches(text))
            {
                // Validate that the matched string is a valid URI before adding
                if (Uri.TryCreate(match.Value, UriKind.Absolute, out _))
                {
                    urls.Add(match.Value);
                }
            }
        }

        // Normalizes a URL by removing fragments and ensuring consistent format
        private static string NormalizeUrl(string url)
        {
            try
            {
                var uri = new Uri(url);
                var builder = new UriBuilder(uri);

                // Remove URL fragment (everything after #) as it's often used for
                // page navigation and doesn't affect the destination
                builder.Fragment = string.Empty;

                return builder.Uri.ToString();
            }
            catch
            {
                // If URL parsing fails (malformed URL), return the original
                // This ensures we don't lose potentially important URLs due to parsing errors
                return url;
            }
        }
    }
}