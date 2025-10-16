using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Options;
using System.ComponentModel.DataAnnotations;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Meter_Reading_Test.Helpers;
using Meter_Reading_Test.Models;

namespace Meter_Reading_Test.Pages.Authenitcation
{
    /// <summary>
    /// Sign In Page Model - Handles user authentication
    /// Manages login form submission and JWT token storage
    /// </summary>
    public class SignInModel : PageModel
    {
        // ========================================
        // DEPENDENCIES & CONFIGURATION
        // Injected services for HTTP communication and logging
        // ========================================
        private readonly HttpClient _httpClient;
        private readonly ILogger<SignInModel> _logger;
        private readonly ApiSettings _apiSettings;

        public SignInModel(HttpClient httpClient, ILogger<SignInModel> logger, IOptions<ApiSettings> apiSettings)
        {
            _httpClient = httpClient;
            _logger = logger;
            _apiSettings = apiSettings.Value;
            
            // Log configuration values for debugging
            _logger.LogInformation("API Configuration loaded - BackendBaseUrl: {BackendBaseUrl}, LoginEndpoint: {LoginEndpoint}", 
                _apiSettings.BackendBaseUrl, _apiSettings.LoginEndpoint);
        }

        // ========================================
        // FORM PROPERTIES
        // Data-bound properties for login form
        // ========================================

        /// <summary>
        /// Username input - bound to form field
        /// Required for authentication
        /// </summary>
        [BindProperty]
        [Required(ErrorMessage = "Username is required")]
        public string Username { get; set; } = string.Empty;

        /// <summary>
        /// Password input - bound to form field
        /// Required for authentication, masked in UI
        /// </summary>
        [BindProperty]
        [Required(ErrorMessage = "Password is required")]
        [DataType(DataType.Password)]
        public string Password { get; set; } = string.Empty;

        /// <summary>
        /// Remember Me checkbox - bound to form field
        /// Determines session persistence (currently stored in cookie)
        /// </summary>
        [BindProperty]
        public bool RememberMe { get; set; }

        /// <summary>
        /// Error message for display to user
        /// Populated when authentication fails
        /// </summary>
        public string? ErrorMessage { get; set; }

        // ========================================
        // PAGE HANDLERS
        // HTTP request handlers for page operations
        // ========================================

        /// <summary>
        /// GET request handler - Displays sign-in page
        /// Redirects to admin page if user is already authenticated
        /// </summary>
        public void OnGet()
        {
            // Check if user already has valid authentication cookie
            if (AuthHelper.IsAuthenticated(HttpContext))
            {
                Response.Redirect("/admin/Admin");
            }
        }

        /// <summary>
        /// POST request handler - Processes login form submission
        /// Authenticates with backend API and stores JWT token on success
        /// </summary>
        public async Task<IActionResult> OnPostAsync()
        {
            // Validate form data before processing
            if (!ModelState.IsValid)
            {
                return Page();
            }

            try
            {
                // Prepare form data for OAuth2 password flow
                // FastAPI expects form-urlencoded data for token endpoint
                var formData = new List<KeyValuePair<string, string>>
                {
                    new KeyValuePair<string, string>("username", Username),
                    new KeyValuePair<string, string>("password", Password)
                };

                var formContent = new FormUrlEncodedContent(formData);

                // Send authentication request to backend
                var loginUrl = $"{_apiSettings.BackendBaseUrl}{_apiSettings.LoginEndpoint}";
                _logger.LogInformation("Attempting to authenticate at URL: {LoginUrl}", loginUrl);
                var response = await _httpClient.PostAsync(loginUrl, formContent);

                if (response.IsSuccessStatusCode)
                {
                    // Parse successful authentication response
                    var responseContent = await response.Content.ReadAsStringAsync();
                    var loginResponse = JsonSerializer.Deserialize<LoginResponse>(responseContent, new JsonSerializerOptions
                    {
                        PropertyNameCaseInsensitive = true
                    });

                    if (loginResponse?.AccessToken != null)
                    {
                        // Store JWT token in secure HTTP-only cookie
                        AuthHelper.SetAuthCookie(HttpContext, loginResponse.AccessToken);
                        _logger.LogInformation("Successfully stored authentication cookie for user: {Username}", Username);

                        // Redirect to admin dashboard
                        _logger.LogInformation("Redirecting to admin page after successful login");
                        return RedirectToPage("/admin/Admin");
                    }
                    else
                    {
                        // Successful response but no token - unexpected
                        ErrorMessage = "Invalid response from authentication server.";
                        return Page();
                    }
                }
                else if (response.StatusCode == System.Net.HttpStatusCode.Unauthorized)
                {
                    // Authentication failed - invalid credentials
                    ErrorMessage = "Invalid username or password. Please try again.";
                    return Page();
                }
                else
                {
                    // Other HTTP error from backend
                    ErrorMessage = "Authentication service is currently unavailable. Please try again later.";
                    _logger.LogError("Login failed with status code: {StatusCode}", response.StatusCode);
                    return Page();
                }
            }
            catch (HttpRequestException ex)
            {
                // Network connectivity issue
                ErrorMessage = "Unable to connect to authentication service. Please check your internet connection.";
                _logger.LogError(ex, "HTTP request exception during login");
                return Page();
            }
            catch (TaskCanceledException ex)
            {
                // Request timeout
                ErrorMessage = "Login request timed out. Please try again.";
                _logger.LogError(ex, "Login request timed out");
                return Page();
            }
            catch (JsonException ex)
            {
                // Invalid JSON response from backend
                ErrorMessage = "Invalid response from authentication server.";
                _logger.LogError(ex, "JSON parsing error during login");
                return Page();
            }
            catch (Exception ex)
            {
                // Catch-all for unexpected errors
                ErrorMessage = "An unexpected error occurred during sign in. Please try again.";
                _logger.LogError(ex, "Unexpected error during login");
                return Page();
            }
        }
    }

    // ========================================
    // DATA TRANSFER OBJECTS (DTOs)
    // Models for API communication
    // ========================================

    /// <summary>
    /// Login Response Model - Received from authentication API
    /// Contains JWT access token and metadata (token type, expiration)
    /// </summary>
    public class LoginResponse
    {
        /// <summary>
        /// JWT access token for authenticated requests
        /// Stored in secure HTTP-only cookie
        /// </summary>
        [JsonPropertyName("access_token")]
        public string? AccessToken { get; set; }
        
        /// <summary>
        /// Token type (typically "Bearer")
        /// Used in Authorization header format
        /// </summary>
        [JsonPropertyName("token_type")]
        public string? TokenType { get; set; }
        
        /// <summary>
        /// Token expiration time in seconds
        /// Used to determine when to refresh token
        /// </summary>
        [JsonPropertyName("expires_in")]
        public int? ExpiresIn { get; set; }
    }
}
