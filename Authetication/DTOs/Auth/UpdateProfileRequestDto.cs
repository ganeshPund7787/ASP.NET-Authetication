using System.ComponentModel.DataAnnotations;

namespace Authetication.DTOs.Auth
{
    public class UpdateProfileRequestDto
    {
        [Required(ErrorMessage = "Full name is required")]
        [StringLength(100, MinimumLength = 2,
            ErrorMessage = "Full name must be between 2 and 100 characters")]
        public string FullName { get; set; } = string.Empty;
    }
}
