using System.ComponentModel.DataAnnotations;

namespace Authetication.DTOs.Auth
{
    public class ChangePasswordRequestDto
    {
        [Required(ErrorMessage = "Current password is required")]
        public string CurrentPassword { get; set; } = string.Empty;

        [Required(ErrorMessage = "New password is required")]
        [MinLength(8, ErrorMessage = "Password must be at least 8 characters")]
        public string NewPassword { get; set; } = string.Empty;

        [Required(ErrorMessage = "Confirm password is required")]
        [Compare("NewPassword",
            ErrorMessage = "New password and confirm password do not match")]
        public string ConfirmNewPassword { get; set; } = string.Empty;
    }
}
