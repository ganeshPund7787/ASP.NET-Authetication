using Authetication.Configuration;
using Authetication.Data;
using Authetication.Interfaces;
using Authetication.Middleware;
using Authetication.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Scalar.AspNetCore;
using System.Text;
using System.Threading.RateLimiting;

var builder = WebApplication.CreateBuilder(args);

// ─── Bind Configuration ───────────────────────────────────────
var jwtSettings = builder.Configuration
    .GetSection("JwtSettings")
    .Get<JwtSettings>()!;

var rateLimitSettings = builder.Configuration
    .GetSection("RateLimiting")
    .Get<RateLimitSettings>()!;

var corsSettings = builder.Configuration
    .GetSection("Cors")
    .Get<CorsSettings>()!;

builder.Services.Configure<JwtSettings>(
    builder.Configuration.GetSection("JwtSettings"));
builder.Services.Configure<RateLimitSettings>(
    builder.Configuration.GetSection("RateLimiting"));
builder.Services.Configure<CorsSettings>(
    builder.Configuration.GetSection("Cors"));

// ─── Register DbContext ───────────────────────────────────────
builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseSqlServer(builder.Configuration
        .GetConnectionString("DefaultConnection")));

// ─── Register Application Services ───────────────────────────
builder.Services.AddScoped<IAuthService, AuthService>();
builder.Services.AddScoped<ITokenService, TokenService>();
builder.Services.AddScoped<IUserService, UserService>();    

// ─── Configure CORS ───────────────────────────────────────────
builder.Services.AddCors(options =>
{
    options.AddPolicy("ProductionPolicy", policy =>
    {
        policy.WithOrigins(corsSettings.AllowedOrigins)
              .AllowAnyHeader()
              .AllowAnyMethod()
              .AllowCredentials();
    });

    // Development only — allow all origins
    options.AddPolicy("DevelopmentPolicy", policy =>
    {
        policy.AllowAnyOrigin()
              .AllowAnyHeader()
              .AllowAnyMethod();
    });
});

// ─── Configure Rate Limiting ──────────────────────────────────
builder.Services.AddRateLimiter(options =>
{
    // Auth endpoints — strict limit (5 requests per minute)
    // Prevents brute force login/register attacks
    options.AddFixedWindowLimiter("AuthLimit", limiterOptions =>
    {
        limiterOptions.Window =
            TimeSpan.FromSeconds(rateLimitSettings.AuthWindowSeconds);
        limiterOptions.PermitLimit = rateLimitSettings.AuthMaxRequests;
        limiterOptions.QueueLimit = 0;
        limiterOptions.QueueProcessingOrder =
            QueueProcessingOrder.OldestFirst;
    });

    // Global limit — all endpoints (100 requests per minute)
    options.AddFixedWindowLimiter("GlobalLimit", limiterOptions =>
    {
        limiterOptions.Window =
            TimeSpan.FromSeconds(rateLimitSettings.GlobalWindowSeconds);
        limiterOptions.PermitLimit = rateLimitSettings.GlobalMaxRequests;
        limiterOptions.QueueLimit = 0;
        limiterOptions.QueueProcessingOrder =
            QueueProcessingOrder.OldestFirst;
    });

    // Response when rate limit exceeded
    options.OnRejected = async (context, cancellationToken) =>
    {
        context.HttpContext.Response.StatusCode = 429;
        context.HttpContext.Response.ContentType = "application/json";

        await context.HttpContext.Response.WriteAsync(
            """
            {
                "statusCode": 429,
                "message": "Too many requests. Please slow down and try again later.",
                "details": null
            }
            """,
            cancellationToken);
    };
});

// ─── Configure JWT Authentication ────────────────────────────
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = jwtSettings.Issuer,
        ValidAudience = jwtSettings.Audience,
        IssuerSigningKey = new SymmetricSecurityKey(
            Encoding.UTF8.GetBytes(jwtSettings.SecretKey)),
        ClockSkew = TimeSpan.Zero
    };
});

// ─── Configure Authorization Policies ────────────────────────
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("AdminOnly", policy =>
        policy.RequireRole("Admin"));

    options.AddPolicy("UserOrAdmin", policy =>
        policy.RequireRole("User", "Admin"));
});

// ─── Register Controllers + OpenAPI ──────────────────────────
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddOpenApi(options =>
{
    options.AddDocumentTransformer((document, context, ct) =>
    {
        document.Info.Title = "AuthSystem API";
        document.Info.Version = "v1";
        return Task.CompletedTask;
    });
});

// ─── Build App ────────────────────────────────────────────────
var app = builder.Build();

// ─── Middleware Pipeline (ORDER MATTERS) ──────────────────────

// 1. Exception handling — must be outermost
app.UseMiddleware<ExceptionMiddleware>();

// 2. Security headers — applied to every response
app.UseMiddleware<SecurityHeadersMiddleware>();

// 3. HTTPS redirection
app.UseHttpsRedirection();

// 4. CORS — before authentication
if (app.Environment.IsDevelopment())
{
    app.UseCors("DevelopmentPolicy");

    app.MapOpenApi();
    app.MapScalarApiReference(options =>
    {
        options.Title = "AuthSystem API";
        options.Theme = ScalarTheme.DeepSpace;
        options.DefaultHttpClient = new(ScalarTarget.CSharp,
                                        ScalarClient.HttpClient);
    });
}
else
{
    app.UseCors("ProductionPolicy");
}

// 5. Rate limiting
app.UseRateLimiter();

// 6. Authentication then Authorization
app.UseAuthentication();
app.UseAuthorization();

// 7. Map controllers
app.MapControllers();

app.Run();