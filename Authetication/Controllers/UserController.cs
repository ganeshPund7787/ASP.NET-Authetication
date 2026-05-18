using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace Authetication.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    [Authorize]                         // ← All endpoints require authentication
    public class UserController : ControllerBase
    {
        // ─── Any authenticated user ───────────────────────────────
        [HttpGet("profile")]
        public IActionResult GetProfile()
        {
            // Extract claims from JWT token
            var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value
                      ?? User.FindFirst("sub")?.Value;
            var email = User.FindFirst(ClaimTypes.Email)?.Value
                     ?? User.FindFirst("email")?.Value;
            var fullName = User.FindFirst("fullName")?.Value;
            var role = User.FindFirst(ClaimTypes.Role)?.Value;

            return Ok(new
            {
                message = "Profile retrieved successfully.",
                profile = new
                {
                    userId,
                    email,
                    fullName,
                    role
                }
            });
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

        // ─── Public inside authenticated controller ────────────────
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