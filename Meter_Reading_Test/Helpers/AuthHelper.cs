using Microsoft.AspNetCore.Http;
using System;

namespace Meter_Reading_Test.Helpers
{
    public static class AuthHelper
    {
        private const string AuthCookieName = "AuthToken";
        private const int CookieExpiryHours = 1;

        /// <summary>
        /// Sets the authentication cookie with the JWT token
        /// </summary>
        /// <param name="context">HTTP context</param>
        /// <param name="token">JWT token to store</param>
        public static void SetAuthCookie(HttpContext context, string token)
        {
            var cookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Strict,
                Expires = DateTime.UtcNow.AddHours(CookieExpiryHours)
            };

            context.Response.Cookies.Append(AuthCookieName, token, cookieOptions);
        }

        /// <summary>
        /// Gets the authentication token from the cookie
        /// </summary>
        /// <param name="context">HTTP context</param>
        /// <returns>JWT token or null if not found</returns>
        public static string? GetAuthToken(HttpContext context)
        {
            return context.Request.Cookies[AuthCookieName];
        }

        /// <summary>
        /// Clears the authentication cookie
        /// </summary>
        /// <param name="context">HTTP context</param>
        public static void ClearAuthCookie(HttpContext context)
        {
            var cookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Strict,
                Expires = DateTime.UtcNow.AddDays(-1) // Set to past date to delete
            };

            context.Response.Cookies.Append(AuthCookieName, "", cookieOptions);
        }

        /// <summary>
        /// Checks if the user is authenticated (has a valid token cookie)
        /// </summary>
        /// <param name="context">HTTP context</param>
        /// <returns>True if authenticated, false otherwise</returns>
        public static bool IsAuthenticated(HttpContext context)
        {
            var token = GetAuthToken(context);
            return !string.IsNullOrEmpty(token);
        }
    }
}
