using PhishingDetectionEngine.Core.Models;
using PhishingDetectionEngine.Core.Interaces;

namespace PhishingDetectionEngine.Core.ServiceModules
{
    public class PhishTankApiService : IPhishtankApiService
    {
        private string ApiKey { get; set; } = string.Empty;
        public async Task PerformLookup(ParsedEmail email)
        {
            throw new NotImplementedException("Not yet done due to not being able to register!");
        }
    }
}


