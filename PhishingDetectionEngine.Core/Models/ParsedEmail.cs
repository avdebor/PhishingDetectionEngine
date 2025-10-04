namespace PhishingDetectionEngine.Core.Models
{
    public class ParsedEmail
    {
        public string Subject { get; set; }
        public string From { get; set; }          
        public string To { get; set; }            
        public string TextBody { get; set; }     
        public string HtmlBody { get; set; }       
        public Dictionary<string, string> Headers { get; set; } = new Dictionary<string, string>();
        public List<EmailAttachment> Attachments { get; set; } = new List<EmailAttachment>();
    }

}
