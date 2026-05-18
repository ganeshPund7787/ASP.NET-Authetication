namespace Authetication.Middleware
{
    public class SecurityHeadersMiddleware
    {
        private readonly RequestDelegate _next;

        public SecurityHeadersMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            // ─── Prevent clickjacking ─────────────────────────────
            context.Response.Headers.Append(
                "X-Frame-Options", "DENY");

            // ─── Prevent MIME type sniffing ───────────────────────
            context.Response.Headers.Append(
                "X-Content-Type-Options", "nosniff");

            // ─── Enable XSS protection in older browsers ──────────
            context.Response.Headers.Append(
                "X-XSS-Protection", "1; mode=block");

            // ─── Control referrer information ─────────────────────
            context.Response.Headers.Append(
                "Referrer-Policy", "strict-origin-when-cross-origin");

            // ─── Restrict powerful browser features ───────────────
            context.Response.Headers.Append(
                "Permissions-Policy",
                "accelerometer=(), camera=(), geolocation=(), " +
                "gyroscope=(), magnetometer=(), microphone=(), " +
                "payment=(), usb=()");

            // ─── Content Security Policy ──────────────────────────
            context.Response.Headers.Append(
                "Content-Security-Policy",
                "default-src 'self'; " +
                "frame-ancestors 'none';");

            // ─── HTTPS strict transport ───────────────────────────
            context.Response.Headers.Append(
                "Strict-Transport-Security",
                "max-age=31536000; includeSubDomains");

            // ─── Remove server identification ─────────────────────
            context.Response.Headers.Remove("Server");
            context.Response.Headers.Remove("X-Powered-By");

            await _next(context);
        }
    }
}
