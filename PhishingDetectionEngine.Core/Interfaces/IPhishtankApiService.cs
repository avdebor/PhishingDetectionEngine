using PhishingDetectionEngine.Core.Models;

namespace PhishingDetectionEngine.Core.Interfaces
{
    public interface IPhishtankApiService
    {
        Task<DetectionResult> PerformLookup(ParsedEmail email);
    }
}

