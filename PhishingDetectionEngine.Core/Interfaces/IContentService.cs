using System.Threading.Tasks;
using PhishingDetectionEngine.Core.Models;

namespace PhishingDetectionEngine.Core.Interfaces
{
    public interface IContentService
    {
        Task<DetectionResult> AnalyzeContent(ParsedEmail email);
    }
}