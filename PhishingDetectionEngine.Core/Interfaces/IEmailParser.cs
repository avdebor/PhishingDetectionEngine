using PhishingDetectionEngine.Core.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PhishingDetectionEngine.Core.Interfaces
{
    public interface IEmailParser
    {
        Task<ParsedEmail> ParseAsync(
            string fileName,
            Stream contentStream);

    }
}
