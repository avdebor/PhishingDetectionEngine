using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace PhishingDetectionEngine.Core.Utilities
{
    public class TextFetcherFromHTMLContent
    {
        public static string GetPlainTextFromHtmlContent(string html)
        {
            if (string.IsNullOrWhiteSpace(html))
                return string.Empty;

            html = Regex.Replace(html, "<(script|style)[^>]*>.*?</\\1>", string.Empty,
                RegexOptions.Singleline | RegexOptions.IgnoreCase);
            html = Regex.Replace(html, "<[^>]+>", " ");

            html = WebUtility.HtmlDecode(html);
            html = Regex.Replace(html, "\\s+", " ").Trim();

            return html;
        }
    }
}
