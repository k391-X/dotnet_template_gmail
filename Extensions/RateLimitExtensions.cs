using System.Threading.RateLimiting;
using Microsoft.AspNetCore.RateLimiting;

namespace SmtpGmailDemo.Extensions
{
    public static class RateLimitExtensions
    {
        public static IServiceCollection AddAppRateLimiting(this IServiceCollection services)
        {
            services.AddRateLimiter(options =>
            {
                // Chính sách: Giới hạn đăng ký tài khoản
                options.AddPolicy("registerLimiter", context =>
                {
                    var ipAddress = context.Connection.RemoteIpAddress?.ToString() ?? "unknown";

                    return RateLimitPartition.GetFixedWindowLimiter(ipAddress, _ => new FixedWindowRateLimiterOptions
                    {
                        PermitLimit = 1, // Tối đa 5 request
                        Window = TimeSpan.FromMinutes(5), // Trong 5 phút
                        QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                        QueueLimit = 0 // Không xếp hàng
                    });
                });

                // Chính sách: quên mật khẩu
                options.AddPolicy("forgotPasswordLimiter", context =>
                {
                    var ipAddress = context.Connection.RemoteIpAddress?.ToString() ?? "unknown";

                    return RateLimitPartition.GetFixedWindowLimiter(ipAddress, _ => new FixedWindowRateLimiterOptions
                    {
                        PermitLimit = 5,
                        Window = TimeSpan.FromMinutes(5),
                        QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                        QueueLimit = 0
                    });
                });

                // Chính sách: đổi mật khẩu
                options.AddPolicy("resetPasswordLimiter", context =>
                {
                    var ipAddress = context.Connection.RemoteIpAddress?.ToString() ?? "unknown";

                    return RateLimitPartition.GetFixedWindowLimiter(ipAddress, _ => new FixedWindowRateLimiterOptions
                    {
                        PermitLimit = 5,
                        Window = TimeSpan.FromMinutes(5),
                        QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                        QueueLimit = 0
                    });
                });

                // Custom phản hồi khi bị giới hạn
                options.OnRejected = async (context, token) =>
                {
                    context.HttpContext.Response.StatusCode = StatusCodes.Status429TooManyRequests;
                    context.HttpContext.Response.ContentType = "application/json";

                    var ip = context.HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
                    Console.WriteLine($"[RATE LIMIT] IP {ip} bị chặn vì gửi request quá nhanh.");

                    await context.HttpContext.Response.WriteAsync(
                         "{\"error\":\"Too many requests. Please try again later.\"}", token);
                };
            });

            return services;
        }
    }
}
