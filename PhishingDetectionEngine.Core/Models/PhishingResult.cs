using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PhishingDetectionEngine.Core.Models
{
    public class PhishingResult
    {
        public double OverallScore { get; set; }
        public List<ModuleScore> ModuleScores { get; set; } = new();
        public string Verdict => OverallScore >= 70 ? "Likely Phishing" : "Likely Safe";
    }
}
