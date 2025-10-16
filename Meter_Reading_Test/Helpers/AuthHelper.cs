using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using System;

namespace Meter_Reading_Test.Helpers
{
    /// <summary>
    /// Authentication Helper Class
    /// Provides static methods for managing JWT tokens in HTTP-only cookies
    /// Used across the application for secure authentication state management
    /// </summary>
    public static class AuthHelper
    {
        // ========================================
        // CONSTANTS
        // Configuration values for cookie management
        // ========================================
        
        /// <summary>
        /// Cookie name for storing JWT authentication token
        /// Used consistently across the application for token retrieval
        /// </summary>
        private const string AuthCookieName = "AuthToken";
        
        /// <summary>
        /// Cookie expiration time in hours (default: 1 hour)
        /// Aligned with JWT token expiration for automatic logout
        /// </summary>
        private const int CookieExpiryHours = 1;

        // ========================================
        // PUBLIC METHODS
        // Cookie management operations
        // ========================================

        /// <summary>
        /// Stores JWT token in secure HTTP-only cookie
        /// Cookie is protected against XSS attacks and CSRF
        /// </summary>
        /// <param name="context">Current HTTP context</param>
        /// <param name="token">JWT token string to store</param>
        public static void SetAuthCookie(HttpContext context, string token)
        {
            // Configure secure cookie options
            var cookieOptions = new CookieOptions
            {
                HttpOnly = true,        // Prevents JavaScript access (XSS protection)
                Secure = context.Request.IsHttps,  // Only require HTTPS when actually using HTTPS
                SameSite = SameSiteMode.None,      // Allow cross-origin requests (needed for separate EC2 instances)
                Expires = DateTime.UtcNow.AddHours(CookieExpiryHours),  // Auto-expiration
                Path = "/",             // Make cookie available for all paths
                Domain = null           // Don't restrict domain to allow cross-origin
            };

            // Store token in cookie
            context.Response.Cookies.Append(AuthCookieName, token, cookieOptions);
        }

        /// <summary>
        /// Retrieves JWT token from authentication cookie
        /// Returns null if cookie doesn't exist or has expired
        /// </summary>
        /// <param name="context">Current HTTP context</param>
        /// <returns>JWT token string or null if not found</returns>
        public static string? GetAuthToken(HttpContext context)
        {
            return context.Request.Cookies[AuthCookieName];
        }

        /// <summary>
        /// Removes authentication cookie by setting past expiration date
        /// Used during logout or when token becomes invalid
        /// </summary>
        /// <param name="context">Current HTTP context</param>
        public static void ClearAuthCookie(HttpContext context)
        {
            // Set cookie with past expiration date to delete it
            var cookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Secure = context.Request.IsHttps,
                SameSite = SameSiteMode.None,
                Path = "/",
                Domain = null,
                Expires = DateTime.UtcNow.AddDays(-1)  // Past date triggers deletion
            };

            // Overwrite cookie with empty value and past date
            context.Response.Cookies.Append(AuthCookieName, "", cookieOptions);
        }

        /// <summary>
        /// Checks if user has valid authentication cookie
        /// Quick check for authentication state without backend verification
        /// </summary>
        /// <param name="context">Current HTTP context</param>
        /// <returns>True if auth cookie exists with value, false otherwise</returns>
        public static bool IsAuthenticated(HttpContext context)
        {
            var token = GetAuthToken(context);
            var hasToken = !string.IsNullOrEmpty(token);
            
            // Debug logging
            var logger = context.RequestServices.GetService<ILogger<object>>();
            logger?.LogInformation("AuthHelper.IsAuthenticated: hasToken={HasToken}, tokenLength={TokenLength}, cookies={Cookies}", 
                hasToken, token?.Length ?? 0, string.Join(", ", context.Request.Cookies.Keys));
            
            return hasToken;
        }
    }
}
