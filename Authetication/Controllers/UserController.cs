using Authetication.DTOs.Auth;
using Authetication.Interfaces;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace Authetication.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    [Authorize]
    public class UserController : ControllerBase
    {
        private readonly IUserService _userService;

        public UserController(IUserService userService)
        {
            _userService = userService;
        }

        // ─── Helper — extract userId from JWT claims ───────────────
        private int GetUserId()
        {
            var userIdClaim =
                User.FindFirst("sub")?.Value ??
                User.FindFirst(ClaimTypes.NameIdentifier)?.Value;

            if (string.IsNullOrEmpty(userIdClaim))
                throw new UnauthorizedAccessException("Invalid token claims.");

            return int.Parse(userIdClaim);
        }

        // ─── Get Profile ──────────────────────────────────────────
        [HttpGet("profile")]
        public async Task<IActionResult> GetProfile()
        {
            var userId = GetUserId();
            var profile = await _userService.GetProfileAsync(userId);

            return Ok(new
            {
                message = "Profile retrieved successfully.",
                data = profile
            });
        }

        // ─── Update Profile ───────────────────────────────────────
        [HttpPut("profile")]
        public async Task<IActionResult> UpdateProfile(
            [FromBody] UpdateProfileRequestDto request)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var userId = GetUserId();
            var updated = await _userService.UpdateProfileAsync(userId, request);

            return Ok(new
            {
                message = "Profile updated successfully.",
                data = updated
            });
        }

        // ─── Change Password ──────────────────────────────────────
        [HttpPut("change-password")]
        public async Task<IActionResult> ChangePassword(
            [FromBody] ChangePasswordRequestDto request)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var userId = GetUserId();
            await _userService.ChangePasswordAsync(userId, request);

            return Ok(new
            {
                message = "Password changed successfully. " +
                          "Please login again on all devices."
            });
        }

        // ─── Delete Account ───────────────────────────────────────
        [HttpDelete("account")]
        public async Task<IActionResult> DeleteAccount()
        {
            var userId = GetUserId();
            await _userService.DeleteAccountAsync(userId);

            // Clear cookies if using cookie auth
            Response.Cookies.Delete("accessToken");
            Response.Cookies.Delete("refreshToken");

            return Ok(new { message = "Account deleted successfully." });
        }

        // ─── Admin only ───────────────────────────────────────────
        [HttpGet("admin/dashboard")]
        [Authorize(Roles = "Admin")]
        public IActionResult AdminDashboard()
        {
            return Ok(new
            {
                message = "Welcome to Admin Dashboard.",
                data = "This is sensitive admin data."
            });
        }

        // ─── User or Admin ────────────────────────────────────────
        [HttpGet("dashboard")]
        [Authorize(Policy = "UserOrAdmin")]
        public IActionResult UserDashboard()
        {
            var email = User.FindFirst(ClaimTypes.Email)?.Value
                     ?? User.FindFirst("email")?.Value;

            return Ok(new
            {
                message = $"Welcome {email}!",
                data = "This is your personal dashboard."
            });
        }

        // ─── Public ───────────────────────────────────────────────
        [HttpGet("public-info")]
        [AllowAnonymous]
        public IActionResult PublicInfo()
        {
            return Ok(new
            {
                message = "This endpoint is public — no token needed."
            });
        }
    }
}