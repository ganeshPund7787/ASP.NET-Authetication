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
    }
}