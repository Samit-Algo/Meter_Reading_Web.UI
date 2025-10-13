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
    public class SignInModel : PageModel
    {
        private readonly HttpClient _httpClient;
        private readonly ILogger<SignInModel> _logger;
        private readonly ApiSettings _apiSettings;

        public SignInModel(HttpClient httpClient, ILogger<SignInModel> logger, IOptions<ApiSettings> apiSettings)
        {
            _httpClient = httpClient;
            _logger = logger;
            _apiSettings = apiSettings.Value;
        }

        [BindProperty]
        [Required(ErrorMessage = "Username is required")]
        public string Username { get; set; } = string.Empty;

        [BindProperty]
        [Required(ErrorMessage = "Password is required")]
        [DataType(DataType.Password)]
        public string Password { get; set; } = string.Empty;

        [BindProperty]
        public bool RememberMe { get; set; }

        public string? ErrorMessage { get; set; }

        public void OnGet()
        {
            // Check if user is already authenticated
            if (AuthHelper.IsAuthenticated(HttpContext))
            {
                Response.Redirect("/admin/Admin");
            }
        }

        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid)
            {
                return Page();
            }

            try
            {
                // Prepare form data for FastAPI backend
                var formData = new List<KeyValuePair<string, string>>
                {
                    new KeyValuePair<string, string>("username", Username),
                    new KeyValuePair<string, string>("password", Password)
                };

                var formContent = new FormUrlEncodedContent(formData);

                // Send login request to FastAPI backend
                var response = await _httpClient.PostAsync($"{_apiSettings.BackendBaseUrl}{_apiSettings.LoginEndpoint}", formContent);

                if (response.IsSuccessStatusCode)
                {
                    var responseContent = await response.Content.ReadAsStringAsync();
                    var loginResponse = JsonSerializer.Deserialize<LoginResponse>(responseContent, new JsonSerializerOptions
                    {
                        PropertyNameCaseInsensitive = true
                    });

                    if (loginResponse?.AccessToken != null)
                    {
                        // Store JWT token in secure cookie
                        AuthHelper.SetAuthCookie(HttpContext, loginResponse.AccessToken);

                        // Redirect to admin page
                        return RedirectToPage("/admin/Admin");
                    }
                    else
                    {
                        ErrorMessage = "Invalid response from authentication server.";
                        return Page();
                    }
                }
                else if (response.StatusCode == System.Net.HttpStatusCode.Unauthorized)
                {
                    ErrorMessage = "Invalid username or password. Please try again.";
                    return Page();
                }
                else
                {
                    ErrorMessage = "Authentication service is currently unavailable. Please try again later.";
                    _logger.LogError("Login failed with status code: {StatusCode}", response.StatusCode);
                    return Page();
                }
            }
            catch (HttpRequestException ex)
            {
                ErrorMessage = "Unable to connect to authentication service. Please check your internet connection.";
                _logger.LogError(ex, "HTTP request exception during login");
                return Page();
            }
            catch (TaskCanceledException ex)
            {
                ErrorMessage = "Login request timed out. Please try again.";
                _logger.LogError(ex, "Login request timed out");
                return Page();
            }
            catch (JsonException ex)
            {
                ErrorMessage = "Invalid response from authentication server.";
                _logger.LogError(ex, "JSON parsing error during login");
                return Page();
            }
            catch (Exception ex)
            {
                ErrorMessage = "An unexpected error occurred during sign in. Please try again.";
                _logger.LogError(ex, "Unexpected error during login");
                return Page();
            }
        }
    }

    public class LoginResponse
    {
        [JsonPropertyName("access_token")]
        public string? AccessToken { get; set; }
        
        [JsonPropertyName("token_type")]
        public string? TokenType { get; set; }
        
        [JsonPropertyName("expires_in")]
        public int? ExpiresIn { get; set; }
    }
}
