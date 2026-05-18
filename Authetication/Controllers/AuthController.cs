using Authetication.DTOs.Auth;
using Authetication.Interfaces;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Authetication.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly IAuthService _authService;

        public AuthController(IAuthService authService)
        {
            _authService = authService;
        }

        // ─── Register ─────────────────────────────────────────────
        [HttpPost("register")]
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

        // ─── Login ────────────────────────────────────────────────
        [HttpPost("login")]
        public async Task<IActionResult> Login(
            [FromBody] LoginRequestDto request)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var result = await _authService.LoginAsync(request);
            return Ok(result);
        }

        // ─── Refresh Token ────────────────────────────────────────
        [HttpPost("refresh-token")]
        public async Task<IActionResult> RefreshToken(
            [FromBody] RefreshTokenRequestDto request)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var result = await _authService.RefreshTokenAsync(request);
            return Ok(result);
        }

        // ─── Logout ───────────────────────────────────────────────
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