using Authetication.DTOs.Auth;

namespace Authetication.Interfaces
{
    public interface IUserService
    {
        Task<UserProfileDto> GetProfileAsync(int userId);
        Task<UserProfileDto> UpdateProfileAsync(
            int userId, UpdateProfileRequestDto request);
        Task<bool> ChangePasswordAsync(
            int userId, ChangePasswordRequestDto request);
        Task<bool> DeleteAccountAsync(int userId);
    }
}
