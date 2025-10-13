namespace Meter_Reading_Test.Models
{
    public class ApiSettings
    {
        public string BackendBaseUrl { get; set; } = string.Empty;
        public string LoginEndpoint { get; set; } = "/auth/login";
        public string ExtractMeterEndpoint { get; set; } = "/meter_reading_test/upload-meter-image";
        public string VerifyTokenEndpoint { get; set; } = "/auth/verify-token";
        public int RequestTimeoutSeconds { get; set; } = 30;
    }
}
