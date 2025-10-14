namespace Meter_Reading_Test.Models
{
    /// <summary>
    /// API Configuration Settings Model
    /// Stores backend API endpoints and configuration from appsettings.json
    /// Injected as IOptions&lt;ApiSettings&gt; throughout the application
    /// </summary>
    public class ApiSettings
    {
        /// <summary>
        /// Backend API base URL (e.g., "http://localhost:8000")
        /// Combined with endpoint paths for full API URLs
        /// </summary>
        public string BackendBaseUrl { get; set; } = string.Empty;
        
        /// <summary>
        /// Login endpoint path (e.g., "/auth/login")
        /// Used for user authentication and JWT token retrieval
        /// </summary>
        public string LoginEndpoint { get; set; } = "/auth/login";
        
        /// <summary>
        /// Meter reading extraction endpoint path (e.g., "/meter_reading_test/upload-meter-image")
        /// Used for uploading meter images and receiving OCR results
        /// </summary>
        public string ExtractMeterEndpoint { get; set; } = "/meter_reading_test/upload-meter-image";
        
        /// <summary>
        /// Token verification endpoint path (e.g., "/auth/verify-token")
        /// Used to validate JWT tokens and check expiration
        /// </summary>
        public string VerifyTokenEndpoint { get; set; } = "/auth/verify-token";
        
        /// <summary>
        /// HTTP request timeout in seconds (default: 30 seconds)
        /// Applied to all HTTP client requests to prevent hanging
        /// </summary>
        public int RequestTimeoutSeconds { get; set; } = 30;
    }
}
