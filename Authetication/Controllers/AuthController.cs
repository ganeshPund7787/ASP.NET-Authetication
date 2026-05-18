using Authetication.DTOs.Auth;
using Authetication.Interfaces;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;

namespace AuthSystem.API.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    [EnableRateLimiting("GlobalLimit")]
    public class AuthController : ControllerBase
    {
        private readonly IAuthService _authService;
        private readonly IConfiguration _configuration;

        public AuthController(
            IAuthService authService,
            IConfiguration configuration)
        {
            _authService = authService;
            _configuration = configuration;
        }

        // ─── Register ─────────────────────────────────────────────
        [HttpPost("register")]
        [EnableRateLimiting("AuthLimit")]
        public async Task<IActionResult> Register(
            [FromBody] RegisterRequestDto request)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var result = await _authService.RegisterAsync(request);

            return Ok(new
            {
                message = "Registration successful.",
                user = new
                {
                    result.FullName,
                    result.Email,
                    result.Role
                }
            });
        }

        // ─── Login — Returns tokens in JSON body ──────────────────
        [HttpPost("login")]
        [EnableRateLimiting("AuthLimit")]
        public async Task<IActionResult> Login(
            [FromBody] LoginRequestDto request)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var result = await _authService.LoginAsync(request);
            return Ok(result);
        }

        // ─── Login — Sets tokens in HttpOnly Cookies ──────────────
        [HttpPost("login-cookie")]
        [EnableRateLimiting("AuthLimit")]
        public async Task<IActionResult> LoginWithCookie(
            [FromBody] LoginRequestDto request)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var result = await _authService.LoginAsync(request);

            // ─── Read expiry settings ─────────────────────────────
            var accessExpiryMins = _configuration
                .GetValue<int>("JwtSettings:AccessTokenExpiryMinutes");
            var refreshExpiryDays = _configuration
                .GetValue<int>("JwtSettings:RefreshTokenExpiryDays");

            // ─── Set Access Token Cookie ──────────────────────────
            Response.Cookies.Append("accessToken", result.AccessToken,
                new CookieOptions
                {
                    HttpOnly = true,              // JS cannot read this
                    Secure = false,              // HTTPS only
                    SameSite = SameSiteMode.Strict, // No cross-site requests
                    Expires = DateTime.UtcNow
                        .AddMinutes(accessExpiryMins)
                });

            // ─── Set Refresh Token Cookie ─────────────────────────
            Response.Cookies.Append("refreshToken", result.RefreshToken,
                new CookieOptions
                {
                    HttpOnly = true,
                    Secure = true,
                    SameSite = SameSiteMode.Strict,
                    Expires = DateTime.UtcNow
                        .AddDays(refreshExpiryDays),
                    Path = "/api/auth"      // Only sent to auth endpoints
                });

            // ─── Return user info only — NOT the tokens ───────────
            return Ok(new
            {
                message = "Login successful.",
                user = new
                {
                    result.Email,
                    result.FullName,
                    result.Role,
                    result.AccessTokenExpiry
                }
            });
        }

        // ─── Refresh via Cookie ───────────────────────────────────
        [HttpPost("refresh-cookie")]
        public async Task<IActionResult> RefreshCookie()
        {
            // Read tokens FROM cookies (not request body)
            var accessToken = Request.Cookies["accessToken"];
            var refreshToken = Request.Cookies["refreshToken"];

            if (string.IsNullOrEmpty(accessToken) ||
                string.IsNullOrEmpty(refreshToken))
                return Unauthorized(new
                {
                    message = "Missing authentication cookies."
                });

            var request = new RefreshTokenRequestDto
            {
                AccessToken = accessToken,
                RefreshToken = refreshToken
            };

            var result = await _authService.RefreshTokenAsync(request);

            var accessExpiryMins = _configuration
                .GetValue<int>("JwtSettings:AccessTokenExpiryMinutes");
            var refreshExpiryDays = _configuration
                .GetValue<int>("JwtSettings:RefreshTokenExpiryDays");

            // ─── Set new cookies ──────────────────────────────────
            Response.Cookies.Append("accessToken", result.AccessToken,
                new CookieOptions
                {
                    HttpOnly = true,
                    Secure = true,
                    SameSite = SameSiteMode.Strict,
                    Expires = DateTime.UtcNow.AddMinutes(accessExpiryMins)
                });

            Response.Cookies.Append("refreshToken", result.RefreshToken,
                new CookieOptions
                {
                    HttpOnly = true,
                    Secure = true,
                    SameSite = SameSiteMode.Strict,
                    Expires = DateTime.UtcNow.AddDays(refreshExpiryDays),
                    Path = "/api/auth"
                });

            return Ok(new
            {
                message = "Token refreshed successfully.",
                user = new
                {
                    result.Email,
                    result.FullName,
                    result.Role,
                    result.AccessTokenExpiry
                }
            });
        }

        // ─── Logout — Clears cookies ──────────────────────────────
        [HttpPost("logout-cookie")]
        public async Task<IActionResult> LogoutCookie()
        {
            var refreshToken = Request.Cookies["refreshToken"];

            // Revoke in DB if token exists
            if (!string.IsNullOrEmpty(refreshToken))
            {
                var logoutRequest = new LogoutRequestDto
                {
                    RefreshToken = refreshToken
                };
                await _authService.LogoutAsync(logoutRequest);
            }

            // ─── Delete both cookies from browser ─────────────────
            Response.Cookies.Delete("accessToken", new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Strict
            });

            Response.Cookies.Delete("refreshToken", new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Strict,
                Path = "/api/auth"
            });

            return Ok(new { message = "Logged out successfully." });
        }

        // ─── Standard Refresh Token ───────────────────────────────
        [HttpPost("refresh-token")]
        [EnableRateLimiting("AuthLimit")]
        public async Task<IActionResult> RefreshToken(
            [FromBody] RefreshTokenRequestDto request)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var result = await _authService.RefreshTokenAsync(request);
            return Ok(result);
        }

        // ─── Standard Logout ──────────────────────────────────────
        [HttpPost("logout")]
        [Authorize]
        public async Task<IActionResult> Logout(
            [FromBody] LogoutRequestDto request)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            await _authService.LogoutAsync(request);
            return Ok(new { message = "Logged out successfully." });
        }
    }
}