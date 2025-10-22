using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PhishingDetectionEngine.Core.Models
{
    public class DetectionResult
    {
        public string EmailSubject { get; set; }
        public int Percentage { get; set; }
        public List<string> Flags { get; set; } = new List<string>();
        public DateTime DateOfScan { get; set; }
    }
}
