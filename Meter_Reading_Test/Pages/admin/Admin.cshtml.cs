using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Options;
using System.Text.Json;
using System.Text.Json.Serialization;
using Meter_Reading_Test.Helpers;
using Meter_Reading_Test.Models;

namespace Meter_Reading_Test.Pages
{
    /// <summary>
    /// Admin Page Model - Handles meter reading OCR functionality
    /// Manages file uploads, API communication, and user authentication
    /// </summary>
    public class AdminModel : PageModel
    {
        // ========================================
        // DEPENDENCIES & CONFIGURATION
        // Injected services for HTTP communication and logging
        // ========================================
        private readonly HttpClient _httpClient;
        private readonly ILogger<AdminModel> _logger;
        private readonly ApiSettings _apiSettings;

        public AdminModel(HttpClient httpClient, ILogger<AdminModel> logger, IOptions<ApiSettings> apiSettings)
        {
            _httpClient = httpClient;
            _logger = logger;
            _apiSettings = apiSettings.Value;
        }

        // ========================================
        // PUBLIC PROPERTIES
        // Bound properties for form data and UI state
        // ========================================
        
        [BindProperty]
        public IFormFile? UploadedFile { get; set; }

        public string? ExtractedReading { get; set; }
        public string? ErrorMessage { get; set; }
        public bool IsUploading { get; set; }
        
        // API Configuration for client-side JavaScript
        public string ApiBaseUrl => _apiSettings.BackendBaseUrl;
        public string ExtractMeterEndpoint => _apiSettings.ExtractMeterEndpoint;

        // ========================================
        // PAGE HANDLERS
        // HTTP request handlers for page operations
        // ========================================

        /// <summary>
        /// GET request handler - Validates user authentication on page load
        /// Verifies JWT token with backend and redirects to login if invalid
        /// </summary>
        public async Task<IActionResult> OnGetAsync()
        {
            // Check if user has authentication cookie
            if (!AuthHelper.IsAuthenticated(HttpContext))
            {
                return RedirectToPage("/Authenitcation/SignIn");
            }

            // Verify token with backend for security
            var token = AuthHelper.GetAuthToken(HttpContext);
            if (!string.IsNullOrEmpty(token))
            {
                var verifyResult = await VerifyTokenWithDetailsAsync(token);
                if (!verifyResult.IsValid)
                {
                    // Token expired or invalid - clear cookie and redirect
                    AuthHelper.ClearAuthCookie(HttpContext);
                    return RedirectToPage("/Authenitcation/SignIn");
                }
                
                // Store username for display in layout
                ViewData["Username"] = verifyResult.Username ?? "Admin";
            }

            return Page();
        }

        /// <summary>
        /// POST request handler - Processes uploaded meter image file
        /// Validates file, sends to backend API, and returns OCR result
        /// </summary>
        public async Task<IActionResult> OnPostUploadAsync()
        {
            // Verify user is authenticated before processing
            if (!AuthHelper.IsAuthenticated(HttpContext))
            {
                return RedirectToPage("/Authenitcation/SignIn");
            }

            // Validate file selection
            if (UploadedFile == null || UploadedFile.Length == 0)
            {
                ErrorMessage = "Please select a file to upload.";
                return Page();
            }

            // Validate file type - only accept image files
            var allowedExtensions = new[] { ".jpg", ".jpeg", ".png", ".bmp", ".gif" };
            var fileExtension = Path.GetExtension(UploadedFile.FileName).ToLowerInvariant();
            
            if (!allowedExtensions.Contains(fileExtension))
            {
                ErrorMessage = "Please upload a valid image file (JPG, PNG, BMP, GIF).";
                return Page();
            }

            // Validate file size - max 10MB to prevent memory issues
            if (UploadedFile.Length > 10 * 1024 * 1024)
            {
                ErrorMessage = "File size must be less than 10MB.";
                return Page();
            }

            try
            {
                IsUploading = true;

                // Get JWT token from secure cookie
                var token = AuthHelper.GetAuthToken(HttpContext);
                if (string.IsNullOrEmpty(token))
                {
                    // Missing token - redirect to login
                    AuthHelper.ClearAuthCookie(HttpContext);
                    return RedirectToPage("/Authenitcation/SignIn");
                }

                // Verify token is still valid before API call
                var isTokenValid = await VerifyTokenAsync(token);
                if (!isTokenValid)
                {
                    // Invalid or expired token - redirect to login
                    AuthHelper.ClearAuthCookie(HttpContext);
                    return RedirectToPage("/Authenitcation/SignIn");
                }

                // Prepare multipart form data for file upload
                using var formData = new MultipartFormDataContent();
                using var fileStream = UploadedFile.OpenReadStream();
                using var streamContent = new StreamContent(fileStream);
                
                streamContent.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue(UploadedFile.ContentType);
                formData.Add(streamContent, "file", UploadedFile.FileName);

                // Set JWT authorization header for API request
                _httpClient.DefaultRequestHeaders.Authorization = 
                    new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);

                // Send POST request to FastAPI backend
                var extractUrl = $"{_apiSettings.BackendBaseUrl}{_apiSettings.ExtractMeterEndpoint}";
                _logger.LogInformation("Attempting to extract meter reading at URL: {ExtractUrl}", extractUrl);
                var response = await _httpClient.PostAsync(extractUrl, formData);

                if (response.IsSuccessStatusCode)
                {
                    // Parse successful response
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
                    // Token rejected by backend - redirect to login
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
                // Network connectivity issue
                ErrorMessage = "Unable to connect to the processing service. Please check your internet connection.";
                _logger.LogError(ex, "HTTP request exception during meter extraction");
            }
            catch (TaskCanceledException ex)
            {
                // Request timeout - suggest smaller image
                ErrorMessage = "Request timed out. Please try again with a smaller image.";
                _logger.LogError(ex, "Meter extraction request timed out");
            }
            catch (JsonException ex)
            {
                // Invalid JSON response from backend
                ErrorMessage = "Invalid response from processing service.";
                _logger.LogError(ex, "JSON parsing error during meter extraction");
            }
            catch (Exception ex)
            {
                // Catch-all for unexpected errors
                ErrorMessage = "An unexpected error occurred while processing the image.";
                _logger.LogError(ex, "Unexpected error during meter extraction");
            }
            finally
            {
                IsUploading = false;
                // Clean up authorization header for security
                _httpClient.DefaultRequestHeaders.Authorization = null;
            }

            return Page();
        }

        /// <summary>
        /// POST request handler - Signs out the current user
        /// Clears authentication cookie and redirects to login page
        /// </summary>
        public IActionResult OnPostSignOut()
        {
            AuthHelper.ClearAuthCookie(HttpContext);
            return RedirectToPage("/Authenitcation/SignIn");
        }

        // ========================================
        // PRIVATE HELPER METHODS
        // Token verification and validation logic
        // ========================================

        /// <summary>
        /// Verifies JWT token with backend - simplified version
        /// Returns true if token is valid, false otherwise
        /// </summary>
        private async Task<bool> VerifyTokenAsync(string token)
        {
            var result = await VerifyTokenWithDetailsAsync(token);
            return result.IsValid;
        }

        /// <summary>
        /// Verifies JWT token with backend and returns detailed information
        /// Includes token validity status and username from token claims
        /// </summary>
        private async Task<TokenVerificationResult> VerifyTokenWithDetailsAsync(string token)
        {
            try
            {
                // Prepare token verification request
                var verifyRequest = new TokenVerifyRequest { Token = token };
                var jsonContent = JsonSerializer.Serialize(verifyRequest);
                var content = new StringContent(jsonContent, System.Text.Encoding.UTF8, "application/json");

                _logger.LogInformation("Sending token verification request: {JsonContent}", jsonContent);

                // Send verification request to backend
                var response = await _httpClient.PostAsync($"{_apiSettings.BackendBaseUrl}{_apiSettings.VerifyTokenEndpoint}", content);
                
                _logger.LogInformation("Token verification response status: {StatusCode}", response.StatusCode);
                
                if (response.IsSuccessStatusCode)
                {
                    // Parse verification response
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
                    // Log verification failure
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

    // ========================================
    // DATA TRANSFER OBJECTS (DTOs)
    // Models for API communication
    // ========================================

    /// <summary>
    /// Response model for meter reading extraction API
    /// Contains the extracted reading, confidence level, and optional message
    /// </summary>
    public class MeterExtractionResponse
    {
        public string? Reading { get; set; }
        public double? Confidence { get; set; }
        public string? Message { get; set; }
    }

    /// <summary>
    /// Request model for token verification API
    /// Sends JWT token to backend for validation
    /// </summary>
    public class TokenVerifyRequest
    {
        [JsonPropertyName("token")]
        public string Token { get; set; } = string.Empty;
    }

    /// <summary>
    /// Response model from token verification API
    /// Returns token validity, username, and expiration time
    /// </summary>
    public class TokenVerifyResponse
    {
        [JsonPropertyName("token_valid")]
        public bool TokenValid { get; set; }
        
        [JsonPropertyName("username")]
        public string? Username { get; set; }
        
        [JsonPropertyName("expires_at")]
        public int ExpiresAt { get; set; }
    }

    /// <summary>
    /// Internal result model for token verification
    /// Simplified version with just validity and username
    /// </summary>
    public class TokenVerificationResult
    {
        public bool IsValid { get; set; }
        public string? Username { get; set; }
    }
}
