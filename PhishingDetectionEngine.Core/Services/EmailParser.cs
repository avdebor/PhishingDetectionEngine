using MimeKit;
using MsgReader.Outlook;
using PhishingDetectionEngine.Core.Models;
using PhishingDetectionEngine.Core.Services.IServices;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PhishingDetectionEngine.Core.Services
{
    public class EmailParser : IEmailParser
    {
        public async Task<ParsedEmail> ParseAsync(string fileName, Stream contentStream, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(fileName))
                throw new ArgumentException("fileName is required", nameof(fileName));

            var extension = Path.GetExtension(fileName)?.ToLowerInvariant();

            if (extension == ".eml")
            {
                return await ParseEmlAsync(contentStream, cancellationToken);
            }
            else if (extension == ".msg")
            {
                return ParseMsg(contentStream);
            }
            else
            {
                throw new NotSupportedException($"Unsupported email format: {extension}");
            }
        }

        private async Task<ParsedEmail> ParseEmlAsync(Stream stream, CancellationToken ct)
        {
            var message = await MimeMessage.LoadAsync(stream, ct);

            var model = new ParsedEmail
            {
                Subject = message.Subject ?? string.Empty,
                From = message.From?.ToString() ?? string.Empty,
                To = message.To?.ToString() ?? string.Empty,
                TextBody = message.TextBody ?? string.Empty,
                HtmlBody = message.HtmlBody ?? string.Empty,
            };

            foreach (var h in message.Headers)
                model.Headers[h.Field] = h.Value;

            foreach (var part in message.BodyParts.Where(p =>
                        p is MimePart mp && mp.IsAttachment))
            {
                var mp = (MimePart)part;

                long size = 0;
                if (mp.Content != null)
                {
                    await using var ms = new MemoryStream();
                    await mp.Content.DecodeToAsync(ms, ct);
                    size = ms.Length;
                }

                model.Attachments.Add(new EmailAttachment
                {
                    FileName = mp.FileName ?? "attachment",
                    ContentType = mp.ContentType?.MimeType ?? "application/octet-stream",
                    Size = size
                });
            }

            return model;
        }

        private ParsedEmail ParseMsg(Stream stream)
        {
            return new ParsedEmail { };
        }
    }


}
