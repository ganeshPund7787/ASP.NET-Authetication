namespace Authetication.Configuration
{
    public class RateLimitSettings
    {
        public int AuthWindowSeconds { get; set; }
        public int AuthMaxRequests { get; set; }
        public int GlobalWindowSeconds { get; set; }
        public int GlobalMaxRequests { get; set; }
    }
}
