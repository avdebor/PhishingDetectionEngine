using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PhishingDetectionEngine.Core.Models
{
    public class ModuleScore
    {
        public string ModuleName { get; set; } = string.Empty;
        public double Score { get; set; }
    }
}
