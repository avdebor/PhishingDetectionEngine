using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using PhishingDetectionEngine.Core;
using System;
using System.ComponentModel.DataAnnotations;
using System.IO;
using System.Threading.Tasks;

namespace PhishingDetectionEngine.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class EmailUploadController : ControllerBase
    {
        private readonly PhishingOrchestrator _orchestrator;

        public EmailUploadController(PhishingOrchestrator orchestrator)
        {
            _orchestrator = orchestrator ?? throw new ArgumentNullException(nameof(orchestrator));
        }

        [HttpPost("upload")]
        [Consumes("multipart/form-data")]
        public async Task<IActionResult> Upload([FromForm] EmailUploadRequest request)
        {
            if (request.File == null || request.File.Length == 0)
                return BadRequest("No file or empty file provided.");

            var extension = Path.GetExtension(request.File.FileName)?.ToLowerInvariant();
            if (extension != ".eml" && extension != ".msg")
                return StatusCode(StatusCodes.Status415UnsupportedMediaType, "Only .eml and .msg files are supported.");

            await using var stream = request.File.OpenReadStream();

            try
            {
                var result = await _orchestrator.AnalyzeEmailAsync(request.File.FileName, stream);
                return Ok(result);
            }
            catch (Exception ex)
            {
                return StatusCode(StatusCodes.Status500InternalServerError, $"Error processing email: {ex.Message}");
            }
        }
    }

    public class EmailUploadRequest
    {
        [Required]
        public IFormFile File { get; set; }
    }
}
