using Authetication.Models;
using Microsoft.IdentityModel.Tokens;
using System.Net;
using System.Text.Json;

namespace Authetication.Middleware
{
    public class ExceptionMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly ILogger<ExceptionMiddleware> _logger;
        private readonly IHostEnvironment _environment;

        public ExceptionMiddleware(
            RequestDelegate next,
            ILogger<ExceptionMiddleware> logger,
            IHostEnvironment environment)
        {
            _next = next;
            _logger = logger;
            _environment = environment;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            try
            {
                // Pass request to next middleware
                await _next(context);
            }
            catch (Exception ex)
            {
                // Log the full exception internally
                _logger.LogError(ex,
                    "Unhandled exception for request {Method} {Path}",
                    context.Request.Method,
                    context.Request.Path);

                // Handle and return clean response
                await HandleExceptionAsync(context, ex);
            }
        }

        private async Task HandleExceptionAsync(
            HttpContext context,
            Exception exception)
        {
            context.Response.ContentType = "application/json";

            var errorResponse = new ErrorResponse
            {
                Timestamp = DateTime.UtcNow
            };

            // ─── Map exception type to HTTP status + message ──────
            switch (exception)
            {
                case UnauthorizedAccessException:
                    errorResponse.StatusCode = (int)HttpStatusCode.Unauthorized;
                    errorResponse.Message = exception.Message;
                    break;

                case InvalidOperationException:
                    errorResponse.StatusCode = (int)HttpStatusCode.Conflict;
                    errorResponse.Message = exception.Message;
                    break;

                case ArgumentException:
                    errorResponse.StatusCode = (int)HttpStatusCode.BadRequest;
                    errorResponse.Message = exception.Message;
                    break;

                case KeyNotFoundException:
                    errorResponse.StatusCode = (int)HttpStatusCode.NotFound;
                    errorResponse.Message = exception.Message;
                    break;

                case SecurityTokenException:
                    errorResponse.StatusCode = (int)HttpStatusCode.Unauthorized;
                    errorResponse.Message = "Invalid or tampered token.";
                    break;

                case NotImplementedException:
                    errorResponse.StatusCode = (int)HttpStatusCode.NotImplemented;
                    errorResponse.Message = "This feature is not yet implemented.";
                    break;

                default:
                    errorResponse.StatusCode = (int)HttpStatusCode.InternalServerError;
                    errorResponse.Message = "An unexpected error occurred. " +
                                              "Please try again later.";
                    break;
            }

            // ─── Include stack trace in Development only ──────────
            errorResponse.Details = _environment.IsDevelopment()
                ? exception.ToString()
                : null;

            // ─── Write response ───────────────────────────────────
            context.Response.StatusCode = errorResponse.StatusCode;

            var jsonOptions = new JsonSerializerOptions
            {
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase
            };

            var jsonResponse = JsonSerializer.Serialize(errorResponse, jsonOptions);
            await context.Response.WriteAsync(jsonResponse);
        }
    }
}
