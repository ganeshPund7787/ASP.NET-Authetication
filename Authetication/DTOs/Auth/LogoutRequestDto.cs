using System.ComponentModel.DataAnnotations;

namespace Authetication.DTOs.Auth
{
    public class LogoutRequestDto
    {
        [Required(ErrorMessage = "Refresh token is required")]
        public string RefreshToken { get; set; } = string.Empty;
    }
}
