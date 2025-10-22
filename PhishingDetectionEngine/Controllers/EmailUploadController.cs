using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using PhishingDetectionEngine.Core.Interfaces;
using PhishingDetectionEngine.Core.Models;
using System;
using System.IO;
using System.Threading.Tasks;

namespace PhishingDetectionEngine.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class EmailUploadController : ControllerBase
    {
        private readonly IEmailParserService _emailParserService;
        //private readonly IPhishtankApiService IPhishtankApiService;

        public EmailUploadController(IEmailParserService emailParserService) //, IPhishtankApiService phishtankApiService)
        {
            _emailParserService = emailParserService ?? throw new ArgumentNullException(nameof(emailParserService));
            //IPhishtankApiService = phishtankApiService ?? throw new ArgumentNullException(nameof(phishtankApiService));
        }

        [HttpPost("upload")]
        [Consumes("multipart/form-data")]
        public async Task<IActionResult> Upload([FromForm] EmailUpload request)
        {
            if (request?.File == null)
                return BadRequest("No file provided.");

            if (request.File.Length == 0)
                return BadRequest("Empty file.");

            var extension = Path.GetExtension(request.File.FileName)?.ToLowerInvariant();
            if (extension != ".eml" && extension != ".msg")
                return StatusCode(StatusCodes.Status415UnsupportedMediaType, "Only .eml and .msg files are supported.");

            await using var stream = request.File.OpenReadStream();

            try
            {
                var parsed = await _emailParserService.ParseAsync(request.File.FileName, stream);
                return Ok(parsed);
                // Perform Phishtank lookup test
                //var test = await IPhishtankApiService.PerformLookup(parsed);
                //return Ok(test);
            }
            catch (NotSupportedException nse)
            {
                return StatusCode(StatusCodes.Status415UnsupportedMediaType, nse.Message);
            }
            catch (Exception ex)
            {
                //TODO: add logger to catch upload errors
                return StatusCode(StatusCodes.Status500InternalServerError, $"Error parsing email: {ex.Message}");
            }
        }
    }
}
