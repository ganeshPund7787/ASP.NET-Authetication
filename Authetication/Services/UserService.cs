using Authetication.Data;
using Authetication.DTOs.Auth;
using Authetication.Helpers;
using Authetication.Interfaces;
using Microsoft.EntityFrameworkCore;

namespace Authetication.Services
{
    public class UserService : IUserService
    {
        private readonly AppDbContext _context;

        public UserService(AppDbContext context)
        {
            _context = context;
        }

        // ─── Get Profile ──────────────────────────────────────────
        public async Task<UserProfileDto> GetProfileAsync(int userId)
        {
            var user = await _context.Users
                .FirstOrDefaultAsync(u => u.Id == userId);

            if (user == null)
                throw new KeyNotFoundException("User not found.");

            return new UserProfileDto
            {
                Id = user.Id,
                FullName = user.FullName,
                Email = user.Email,
                Role = user.Role,
                CreatedAt = user.CreatedAt
            };
        }

        // ─── Update Profile ───────────────────────────────────────
        public async Task<UserProfileDto> UpdateProfileAsync(
            int userId, UpdateProfileRequestDto request)
        {
            var user = await _context.Users
                .FirstOrDefaultAsync(u => u.Id == userId);

            if (user == null)
                throw new KeyNotFoundException("User not found.");

            // Update only allowed fields
            user.FullName = request.FullName.Trim();

            _context.Users.Update(user);
            await _context.SaveChangesAsync();

            return new UserProfileDto
            {
                Id = user.Id,
                FullName = user.FullName,
                Email = user.Email,
                Role = user.Role,
                CreatedAt = user.CreatedAt
            };
        }

        // ─── Change Password ──────────────────────────────────────
        public async Task<bool> ChangePasswordAsync(
            int userId, ChangePasswordRequestDto request)
        {
            var user = await _context.Users
                .FirstOrDefaultAsync(u => u.Id == userId);

            if (user == null)
                throw new KeyNotFoundException("User not found.");

            // Verify current password is correct
            if (!PasswordHelper.VerifyPassword(
                    request.CurrentPassword, user.PasswordHash))
                throw new UnauthorizedAccessException(
                    "Current password is incorrect.");

            // Ensure new password is different
            if (PasswordHelper.VerifyPassword(
                    request.NewPassword, user.PasswordHash))
                throw new InvalidOperationException(
                    "New password must be different from current password.");

            // Hash and save new password
            user.PasswordHash = PasswordHelper.HashPassword(request.NewPassword);

            // Revoke ALL refresh tokens — force re-login on all devices
            var userTokens = await _context.RefreshTokens
                .Where(r => r.UserId == userId && !r.IsRevoked)
                .ToListAsync();

            foreach (var token in userTokens)
                token.IsRevoked = true;

            _context.Users.Update(user);
            _context.RefreshTokens.UpdateRange(userTokens);
            await _context.SaveChangesAsync();

            return true;
        }

        // ─── Delete Account ───────────────────────────────────────
        public async Task<bool> DeleteAccountAsync(int userId)
        {
            var user = await _context.Users
                .FirstOrDefaultAsync(u => u.Id == userId);

            if (user == null)
                throw new KeyNotFoundException("User not found.");

            // Cascade delete removes RefreshTokens automatically
            _context.Users.Remove(user);
            await _context.SaveChangesAsync();

            return true;
        }
    }
}
