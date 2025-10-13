using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Options;
using System.Text.Json;
using System.Text.Json.Serialization;
using Meter_Reading_Test.Helpers;
using Meter_Reading_Test.Models;

namespace Meter_Reading_Test.Pages
{
    public class AdminModel : PageModel
    {
        private readonly HttpClient _httpClient;
        private readonly ILogger<AdminModel> _logger;
        private readonly ApiSettings _apiSettings;

        public AdminModel(HttpClient httpClient, ILogger<AdminModel> logger, IOptions<ApiSettings> apiSettings)
        {
            _httpClient = httpClient;
            _logger = logger;
            _apiSettings = apiSettings.Value;
        }

        [BindProperty]
        public IFormFile? UploadedFile { get; set; }

        public string? ExtractedReading { get; set; }
        public string? ErrorMessage { get; set; }
        public bool IsUploading { get; set; }

        public async Task<IActionResult> OnGetAsync()
        {
            // Check if user is authenticated
            if (!AuthHelper.IsAuthenticated(HttpContext))
            {
                return RedirectToPage("/Authenitcation/SignIn");
            }

            // Verify token with backend
            var token = AuthHelper.GetAuthToken(HttpContext);
            if (!string.IsNullOrEmpty(token))
            {
                var verifyResult = await VerifyTokenWithDetailsAsync(token);
                if (!verifyResult.IsValid)
                {
                    // Token is invalid or expired, clear cookie and redirect to login
                    AuthHelper.ClearAuthCookie(HttpContext);
                    return RedirectToPage("/Authenitcation/SignIn");
                }
                
                // Store username for display in layout
                ViewData["Username"] = verifyResult.Username ?? "Admin";
            }

            return Page();
        }

        public async Task<IActionResult> OnPostUploadAsync()
        {
            // Check authentication first
            if (!AuthHelper.IsAuthenticated(HttpContext))
            {
                return RedirectToPage("/Authenitcation/SignIn");
            }

            if (UploadedFile == null || UploadedFile.Length == 0)
            {
                ErrorMessage = "Please select a file to upload.";
                return Page();
            }

            // Validate file type (optional - add image validation)
            var allowedExtensions = new[] { ".jpg", ".jpeg", ".png", ".bmp", ".gif" };
            var fileExtension = Path.GetExtension(UploadedFile.FileName).ToLowerInvariant();
            
            if (!allowedExtensions.Contains(fileExtension))
            {
                ErrorMessage = "Please upload a valid image file (JPG, PNG, BMP, GIF).";
                return Page();
            }

            // Validate file size (e.g., max 10MB)
            if (UploadedFile.Length > 10 * 1024 * 1024)
            {
                ErrorMessage = "File size must be less than 10MB.";
                return Page();
            }

            try
            {
                IsUploading = true;

                // Get JWT token from cookie
                var token = AuthHelper.GetAuthToken(HttpContext);
                if (string.IsNullOrEmpty(token))
                {
                    // Token is missing, redirect to login
                    AuthHelper.ClearAuthCookie(HttpContext);
                    return RedirectToPage("/Authenitcation/SignIn");
                }

                // Verify token with backend before proceeding
                var isTokenValid = await VerifyTokenAsync(token);
                if (!isTokenValid)
                {
                    // Token is invalid or expired, clear cookie and redirect to login
                    AuthHelper.ClearAuthCookie(HttpContext);
                    return RedirectToPage("/Authenitcation/SignIn");
                }

                // Prepare multipart form data
                using var formData = new MultipartFormDataContent();
                using var fileStream = UploadedFile.OpenReadStream();
                using var streamContent = new StreamContent(fileStream);
                
                streamContent.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue(UploadedFile.ContentType);
                formData.Add(streamContent, "file", UploadedFile.FileName);

                // Set authorization header
                _httpClient.DefaultRequestHeaders.Authorization = 
                    new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);

                // Send request to FastAPI backend
                var response = await _httpClient.PostAsync($"{_apiSettings.BackendBaseUrl}{_apiSettings.ExtractMeterEndpoint}", formData);

                if (response.IsSuccessStatusCode)
                {
                    var responseContent = await response.Content.ReadAsStringAsync();
                    var extractionResponse = JsonSerializer.Deserialize<MeterExtractionResponse>(responseContent, new JsonSerializerOptions
                    {
                        PropertyNameCaseInsensitive = true
                    });

                    if (extractionResponse?.Reading != null)
                    {
                        ExtractedReading = extractionResponse.Reading;
                        ErrorMessage = null; // Clear any previous errors
                    }
                    else
                    {
                        ErrorMessage = "Unable to extract reading from the uploaded image.";
                    }
                }
                else if (response.StatusCode == System.Net.HttpStatusCode.Unauthorized)
                {
                    // Token is invalid, clear cookie and redirect to login
                    AuthHelper.ClearAuthCookie(HttpContext);
                    return RedirectToPage("/Authenitcation/SignIn");
                }
                else
                {
                    ErrorMessage = "Failed to process the image. Please try again.";
                    _logger.LogError("Meter extraction failed with status code: {StatusCode}", response.StatusCode);
                }
            }
            catch (HttpRequestException ex)
            {
                ErrorMessage = "Unable to connect to the processing service. Please check your internet connection.";
                _logger.LogError(ex, "HTTP request exception during meter extraction");
            }
            catch (TaskCanceledException ex)
            {
                ErrorMessage = "Request timed out. Please try again with a smaller image.";
                _logger.LogError(ex, "Meter extraction request timed out");
            }
            catch (JsonException ex)
            {
                ErrorMessage = "Invalid response from processing service.";
                _logger.LogError(ex, "JSON parsing error during meter extraction");
            }
            catch (Exception ex)
            {
                ErrorMessage = "An unexpected error occurred while processing the image.";
                _logger.LogError(ex, "Unexpected error during meter extraction");
            }
            finally
            {
                IsUploading = false;
                // Clear the authorization header for future requests
                _httpClient.DefaultRequestHeaders.Authorization = null;
            }

            return Page();
        }

        public IActionResult OnPostSignOut()
        {
            // Clear authentication cookie and redirect to login
            AuthHelper.ClearAuthCookie(HttpContext);
            return RedirectToPage("/Authenitcation/SignIn");
        }

        /// <summary>
        /// Verifies the JWT token with the backend
        /// </summary>
        /// <param name="token">JWT token to verify</param>
        /// <returns>True if token is valid, false otherwise</returns>
        private async Task<bool> VerifyTokenAsync(string token)
        {
            var result = await VerifyTokenWithDetailsAsync(token);
            return result.IsValid;
        }

        /// <summary>
        /// Verifies the JWT token with the backend and returns detailed information
        /// </summary>
        /// <param name="token">JWT token to verify</param>
        /// <returns>Token verification result with username and validity</returns>
        private async Task<TokenVerificationResult> VerifyTokenWithDetailsAsync(string token)
        {
            try
            {
                var verifyRequest = new TokenVerifyRequest { Token = token };
                var jsonContent = JsonSerializer.Serialize(verifyRequest);
                var content = new StringContent(jsonContent, System.Text.Encoding.UTF8, "application/json");

                _logger.LogInformation("Sending token verification request: {JsonContent}", jsonContent);

                var response = await _httpClient.PostAsync($"{_apiSettings.BackendBaseUrl}{_apiSettings.VerifyTokenEndpoint}", content);
                
                _logger.LogInformation("Token verification response status: {StatusCode}", response.StatusCode);
                
                if (response.IsSuccessStatusCode)
                {
                    var responseContent = await response.Content.ReadAsStringAsync();
                    _logger.LogInformation("Token verification response: {ResponseContent}", responseContent);
                    
                    var verifyResponse = JsonSerializer.Deserialize<TokenVerifyResponse>(responseContent, new JsonSerializerOptions
                    {
                        PropertyNameCaseInsensitive = true
                    });
                    
                    return new TokenVerificationResult
                    {
                        IsValid = verifyResponse?.TokenValid == true,
                        Username = verifyResponse?.Username
                    };
                }
                else
                {
                    var errorContent = await response.Content.ReadAsStringAsync();
                    _logger.LogError("Token verification failed with status {StatusCode}: {ErrorContent}", response.StatusCode, errorContent);
                }
                
                return new TokenVerificationResult { IsValid = false };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error verifying token");
                return new TokenVerificationResult { IsValid = false };
            }
        }
    }

    public class MeterExtractionResponse
    {
        public string? Reading { get; set; }
        public double? Confidence { get; set; }
        public string? Message { get; set; }
    }

    public class TokenVerifyRequest
    {
        [JsonPropertyName("token")]
        public string Token { get; set; } = string.Empty;
    }

    public class TokenVerifyResponse
    {
        [JsonPropertyName("token_valid")]
        public bool TokenValid { get; set; }
        
        [JsonPropertyName("username")]
        public string? Username { get; set; }
        
        [JsonPropertyName("expires_at")]
        public int ExpiresAt { get; set; }
    }

    public class TokenVerificationResult
    {
        public bool IsValid { get; set; }
        public string? Username { get; set; }
    }
}
