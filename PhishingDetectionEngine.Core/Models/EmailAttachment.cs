using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PhishingDetectionEngine.Core.Models
{
    public class EmailAttachment
    {
        public string FileName { get; set; }       
        public string ContentType { get; set; }    
        public long Size { get; set; }             
        public byte[] Content { get; set; }       
    }
}
}
