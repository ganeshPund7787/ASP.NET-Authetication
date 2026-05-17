namespace Authetication.Models
{
    public class RefreshToken
    {
        public int Id { get; set; }
        public string Token { get; set; } = string.Empty;
        public DateTime ExpiresAt { get; set; }
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        public bool IsRevoked { get; set; } = false;
        public bool IsUsed { get; set; } = false;

        // Foreign key — which user owns this token
        public int UserId { get; set; }
        public User User { get; set; } = null!;
    }
}