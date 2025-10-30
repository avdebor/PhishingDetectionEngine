using PhishingDetectionEngine.Core.Models;

namespace PhishingDetectionEngine.Core.Interfaces
{
    public interface IUrlService
    {
        Task<DetectionResult> PerformLookup(ParsedEmail email);
    }
}

