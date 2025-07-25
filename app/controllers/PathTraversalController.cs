using Microsoft.AspNetCore.Mvc;

namespace GdvCsharp.API.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class PathTraversalController : ControllerBase
    {
        private readonly ILogger<PathTraversalController> _logger;

        public PathTraversalController(ILogger<PathTraversalController> logger)
        {
            _logger = logger;
        }

        // VULNERABILITY: Path Traversal - No input validation
        [HttpGet("vuln")]
        public IActionResult GetFileVulnerable(string filename)
        {
            if (string.IsNullOrEmpty(filename))
            {
                return BadRequest("Filename parameter is required");
            }

            try
            {
                // VULNERABLE: No path validation - allows directory traversal
                // Examples of malicious input:
                // - ../../../etc/passwd
                // - ..\\..\\..\\windows\\system32\\drivers\\etc\\hosts
                // - /etc/shadow
                var basePath = Directory.GetCurrentDirectory();
                var filePath = Path.Combine(basePath, "static", filename);

                _logger.LogInformation($"Attempting to read file: {filePath}");

                if (System.IO.File.Exists(filePath))
                {
                    var content = System.IO.File.ReadAllText(filePath);
                    return Ok(new
                    {
                        filename = filename,
                        content = content,
                        fullPath = filePath,
                        vulnerability = "Path traversal allows access to any file on the system"
                    });
                }

                return NotFound($"File '{filename}' not found at path: {filePath}");
            }
            catch (UnauthorizedAccessException)
            {
                return StatusCode(403, new
                {
                    error = "Access denied to file",
                    filename = filename,
                    hint = "This might indicate the file exists but requires elevated permissions"
                });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new
                {
                    error = "Error reading file",
                    details = ex.Message,
                    filename = filename,
                    type = ex.GetType().Name
                });
            }
        }

        // SECURE: Path Traversal Protection
        [HttpGet("solution")]
        public IActionResult GetFileSecure(string filename)
        {
            if (string.IsNullOrEmpty(filename))
            {
                return BadRequest("Filename parameter is required");
            }

            try
            {
                // SECURE: Validate and sanitize filename
                if (filename.Contains("..") || filename.Contains("/") || filename.Contains("\\"))
                {
                    return BadRequest("Invalid filename. Directory traversal sequences not allowed.");
                }

                // SECURE: Only allow specific file extensions
                var allowedExtensions = new[] { ".txt", ".json", ".log", ".md" };
                var extension = Path.GetExtension(filename).ToLowerInvariant();

                if (!allowedExtensions.Contains(extension))
                {
                    return BadRequest($"File extension '{extension}' not allowed. Allowed: {string.Join(", ", allowedExtensions)}");
                }

                // SECURE: Use a restricted base directory
                var basePath = Path.Combine(Directory.GetCurrentDirectory(), "static", "allowed");
                var fullPath = Path.Combine(basePath, filename);

                // SECURE: Ensure the resolved path is still within our allowed directory
                var normalizedBasePath = Path.GetFullPath(basePath);
                var normalizedFullPath = Path.GetFullPath(fullPath);

                if (!normalizedFullPath.StartsWith(normalizedBasePath))
                {
                    return BadRequest("Access denied. Path traversal detected.");
                }

                if (System.IO.File.Exists(fullPath))
                {
                    var content = System.IO.File.ReadAllText(fullPath);
                    return Ok(new
                    {
                        filename = filename,
                        content = content,
                        securityNote = "This endpoint validates input and restricts file access to allowed directories"
                    });
                }

                return NotFound($"File '{filename}' not found in allowed directory");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error accessing file: {filename}", filename);
                return StatusCode(500, "An error occurred while processing your request");
            }
        }

        // VULNERABILITY: Directory Listing
        [HttpGet("list/vuln")]
        public IActionResult ListDirectoryVulnerable(string directory = ".")
        {
            try
            {
                // VULNERABLE: Allows listing any directory on the system
                var targetDirectory = Path.Combine(Directory.GetCurrentDirectory(), directory);

                if (!Directory.Exists(targetDirectory))
                {
                    return NotFound($"Directory '{directory}' not found");
                }

                var files = Directory.GetFiles(targetDirectory, "*", SearchOption.AllDirectories)
                    .Select(f => new
                    {
                        name = Path.GetFileName(f),
                        path = f,
                        size = new FileInfo(f).Length,
                        lastModified = new FileInfo(f).LastWriteTime
                    });

                var directories = Directory.GetDirectories(targetDirectory)
                    .Select(d => new
                    {
                        name = Path.GetFileName(d),
                        path = d,
                        type = "directory"
                    });

                return Ok(new
                {
                    directory = directory,
                    fullPath = targetDirectory,
                    files = files,
                    directories = directories,
                    vulnerability = "Directory listing exposes file system structure"
                });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new
                {
                    error = "Error listing directory",
                    details = ex.Message,
                    directory = directory
                });
            }
        }

        // SECURE: Restricted Directory Listing
        [HttpGet("list/solution")]
        public IActionResult ListDirectorySecure()
        {
            try
            {
                // SECURE: Only list files in a specific allowed directory
                var allowedDirectory = Path.Combine(Directory.GetCurrentDirectory(), "static", "public");

                if (!Directory.Exists(allowedDirectory))
                {
                    return NotFound("Public directory not available");
                }

                var files = Directory.GetFiles(allowedDirectory)
                    .Where(f => !Path.GetFileName(f).StartsWith(".")) // Exclude hidden files
                    .Select(f => new
                    {
                        name = Path.GetFileName(f),
                        extension = Path.GetExtension(f),
                        size = new FileInfo(f).Length,
                        lastModified = new FileInfo(f).LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")
                    });

                return Ok(new
                {
                    directory = "public",
                    files = files,
                    securityNote = "Only public files are listed, no directory traversal allowed"
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error listing public directory");
                return StatusCode(500, "An error occurred while listing files");
            }
        }
    }
}
