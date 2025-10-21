using PhishingDetectionEngine.Core.Models;

namespace PhishingDetectionEngine.Core.Interaces
{
    public interface IPhishtankApiService
    {
        Task<DetectionResult> PerformLookup(ParsedEmail email);
    }
}

