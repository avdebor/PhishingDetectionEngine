using MimeKit;
using MsgReader.Outlook;
using PhishingDetectionEngine.Core.Interfaces;
using PhishingDetectionEngine.Core.Models;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading.Tasks;


namespace PhishingDetectionEngine.Core.ServiceModules
{
    public class EmailParserService : IEmailParserService
    {
        public async Task<ParsedEmail> ParseAsync(string fileName, Stream contentStream)
        {
            if (string.IsNullOrWhiteSpace(fileName))
                throw new ArgumentException("fileName is required", nameof(fileName));

            var extension = Path.GetExtension(fileName)?.ToLowerInvariant();

            if (extension == ".eml")
            {
                return await ParseEmlAsync(contentStream);
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

        private async Task<ParsedEmail> ParseEmlAsync(Stream stream)
        {
            var message = await MimeMessage.LoadAsync(stream);

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
                byte[] contentBytes = Array.Empty<byte>();
                if (mp.Content != null)
                {
                    await using var ms = new MemoryStream();
                    await mp.Content.DecodeToAsync(ms);
                    contentBytes = ms.ToArray();
                    size = contentBytes.LongLength;
                }

                model.Attachments.Add(new EmailAttachment
                {
                    FileName = mp.FileName ?? "attachment",
                    ContentType = mp.ContentType?.MimeType ?? "application/octet-stream",
                    Size = size,
                    Content = contentBytes
                });
            }

            return model;
        }

        private ParsedEmail ParseMsg(Stream stream)
        {
            using var ms = new MemoryStream();
            stream.CopyTo(ms);
            ms.Position = 0;
            Debug.WriteLine("HERE1: ");
            using var msg = new Storage.Message(ms);
            Debug.WriteLine("HERE2: ");

            var model = new ParsedEmail
            {
                Subject = msg.Subject ?? string.Empty,
                From = msg.Sender?.Email ?? msg.Sender?.DisplayName ?? string.Empty,
                To = string.Join(", ",
                            (msg.Recipients ?? Enumerable.Empty<Storage.Recipient>())
                            .Select(r => r.Email ?? r.DisplayName)
                            .Where(s => !string.IsNullOrWhiteSpace(s))),
                TextBody = msg.BodyText ?? string.Empty,
                HtmlBody = msg.BodyHtml ?? string.Empty,
            };
            Debug.WriteLine("HERE3: " + msg.Subject);
            
            model.Headers["MessageId"] = msg.Id ?? string.Empty;
            if (msg.SentOn.HasValue)
                model.Headers["SentOn"] = msg.SentOn.Value.ToString("o");

            var attachments = (msg.Attachments ?? new System.Collections.Generic.List<object>())
                .OfType<Storage.Attachment>();

            foreach (var att in attachments)
            {
                var fileName = att.FileName ?? "attachment";
                var data = att.Data;
                var size = data?.LongLength ?? 0;

                string contentType;
                try
                {
                    contentType = MimeTypes.GetMimeType(fileName);
                }
                catch
                {
                    contentType = "application/octet-stream";
                }

                model.Attachments.Add(new EmailAttachment
                {
                    FileName = fileName,
                    ContentType = contentType,
                    Size = (long)size,
                    Content = data ?? Array.Empty<byte>()
                });
            }

            return model;
        }


    }


}
