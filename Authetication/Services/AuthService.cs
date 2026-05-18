using Authetication.Configuration;
using Authetication.Data;
using Authetication.DTOs.Auth;
using Authetication.Helpers;
using Authetication.Interfaces;
using Authetication.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace Authetication.Services
{
    public class AuthService : IAuthService
    {
        private readonly AppDbContext _context;
        private readonly JwtSettings _jwtSettings;
        private readonly ITokenService _tokenService;

        public AuthService(
            AppDbContext context,
            IOptions<JwtSettings> jwtSettings,
            ITokenService tokenService)
        {
            _context = context;
            _jwtSettings = jwtSettings.Value;
            _tokenService = tokenService;
        }

        // ─── Register ─────────────────────────────────────────────
        public async Task<AuthResponseDto> RegisterAsync(RegisterRequestDto request)
        {
            var existingUser = await _context.Users
                .FirstOrDefaultAsync(u => u.Email == request.Email.ToLower());

            if (existingUser != null)
                throw new InvalidOperationException("Email is already registered.");

            var user = new User
            {
                FullName = request.FullName.Trim(),
                Email = request.Email.ToLower().Trim(),
                PasswordHash = PasswordHelper.HashPassword(request.Password),
                Role = "User",
                CreatedAt = DateTime.UtcNow
            };

            await _context.Users.AddAsync(user);
            await _context.SaveChangesAsync();

            return new AuthResponseDto
            {
                Email = user.Email,
                FullName = user.FullName,
                Role = user.Role,
                AccessToken = string.Empty,
                RefreshToken = string.Empty,
                AccessTokenExpiry = DateTime.UtcNow
            };
        }

        // ─── Login ────────────────────────────────────────────────
        public async Task<AuthResponseDto> LoginAsync(LoginRequestDto request)
        {
            // Step 1: Find user by email
            var user = await _context.Users
                .FirstOrDefaultAsync(u => u.Email == request.Email.ToLower());

            if (user == null)
                throw new UnauthorizedAccessException("Invalid email or password.");

            // Step 2: Verify password
            if (!PasswordHelper.VerifyPassword(request.Password, user.PasswordHash))
                throw new UnauthorizedAccessException("Invalid email or password.");

            // Step 3: Generate tokens
            var accessToken = _tokenService.GenerateAccessToken(user);
            var refreshToken = _tokenService.GenerateRefreshToken();

            // Step 4: Save refresh token to database
            var refreshTokenEntity = new RefreshToken
            {
                Token = refreshToken,
                UserId = user.Id,
                ExpiresAt = DateTime.UtcNow.AddDays(_jwtSettings.RefreshTokenExpiryDays),
                CreatedAt = DateTime.UtcNow,
                IsRevoked = false,
                IsUsed = false
            };

            await _context.RefreshTokens.AddAsync(refreshTokenEntity);
            await _context.SaveChangesAsync();

            // Step 5: Return tokens to client
            return new AuthResponseDto
            {
                AccessToken = accessToken,
                RefreshToken = refreshToken,
                AccessTokenExpiry = DateTime.UtcNow
                    .AddMinutes(_jwtSettings.AccessTokenExpiryMinutes),
                Email = user.Email,
                FullName = user.FullName,
                Role = user.Role
            };
        }

        // ─── Refresh Token ────────────────────────────────────────
        public async Task<AuthResponseDto> RefreshTokenAsync(RefreshTokenRequestDto request)
        {
            // Step 1: Extract claims from expired access token
            var principal = _tokenService
                .GetPrincipalFromExpiredToken(request.AccessToken);

            if (principal == null)
                throw new UnauthorizedAccessException("Invalid access token.");

            // Step 2: Get userId from claims
            var userIdClaim = principal.FindFirst("sub")
                           ?? principal.FindFirst(
                               System.Security.Claims.ClaimTypes.NameIdentifier);

            if (userIdClaim == null)
                throw new UnauthorizedAccessException("Invalid token claims.");

            var userId = int.Parse(userIdClaim.Value);

            // Step 3: Find user in database
            var user = await _context.Users
                .FirstOrDefaultAsync(u => u.Id == userId);

            if (user == null)
                throw new UnauthorizedAccessException("User not found.");

            // Step 4: Find the refresh token in database
            var storedRefreshToken = await _context.RefreshTokens
                .FirstOrDefaultAsync(r =>
                    r.Token == request.RefreshToken &&
                    r.UserId == userId);

            if (storedRefreshToken == null)
                throw new UnauthorizedAccessException("Refresh token not found.");

            // Step 5: Validate refresh token state
            if (storedRefreshToken.IsRevoked)
                throw new UnauthorizedAccessException("Refresh token has been revoked.");

            if (storedRefreshToken.IsUsed)
                throw new UnauthorizedAccessException("Refresh token has already been used.");

            if (storedRefreshToken.ExpiresAt < DateTime.UtcNow)
                throw new UnauthorizedAccessException("Refresh token has expired.");

            // Step 6: Mark old refresh token as used (Token Rotation)
            storedRefreshToken.IsUsed = true;
            _context.RefreshTokens.Update(storedRefreshToken);

            // Step 7: Generate brand new tokens
            var newAccessToken = _tokenService.GenerateAccessToken(user);
            var newRefreshToken = _tokenService.GenerateRefreshToken();

            // Step 8: Save new refresh token to database
            var newRefreshTokenEntity = new RefreshToken
            {
                Token = newRefreshToken,
                UserId = user.Id,
                ExpiresAt = DateTime.UtcNow.AddDays(_jwtSettings.RefreshTokenExpiryDays),
                CreatedAt = DateTime.UtcNow,
                IsRevoked = false,
                IsUsed = false
            };

            await _context.RefreshTokens.AddAsync(newRefreshTokenEntity);
            await _context.SaveChangesAsync();

            // Step 9: Return new tokens
            return new AuthResponseDto
            {
                AccessToken = newAccessToken,
                RefreshToken = newRefreshToken,
                AccessTokenExpiry = DateTime.UtcNow
                    .AddMinutes(_jwtSettings.AccessTokenExpiryMinutes),
                Email = user.Email,
                FullName = user.FullName,
                Role = user.Role
            };
        }

        // ─── Logout ───────────────────────────────────────────────
        public async Task<bool> LogoutAsync(LogoutRequestDto request)
        {
            // Find the refresh token in database
            var storedRefreshToken = await _context.RefreshTokens
                .FirstOrDefaultAsync(r => r.Token == request.RefreshToken);

            // If token doesn't exist — already logged out
            if (storedRefreshToken == null)
                return true;

            // Mark as revoked — can never be used again
            storedRefreshToken.IsRevoked = true;
            _context.RefreshTokens.Update(storedRefreshToken);
            await _context.SaveChangesAsync();

            return true;
        }
    }
}