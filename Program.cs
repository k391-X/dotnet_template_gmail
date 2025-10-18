using SmtpGmailDemo.Services;
using SmtpGmailDemo.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using SmtpGmailDemo.Extensions;
using System.Threading.RateLimiting;

var builder = WebApplication.CreateBuilder(args);

// Gọi extension RateLimiter
builder.Services.AddAppRateLimiting();

// 🟢 Cấu hình email
builder.Services.Configure<EmailSettings>(
    builder.Configuration.GetSection("EmailSettings")
);

builder.Services.AddScoped<EmailService>();
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

// Cấu hình Jwt ở file riêng
builder.Services.AddAppIdentity(builder.Configuration);
builder.Services.AddJwtAuthentication(builder.Configuration);

var app = builder.Build();
app.UseRouting();

// Kích hoạt RateLimiter middleware
app.UseRateLimiter();


app.MapControllerRoute(
    name: "Home",
    pattern: "/",
    defaults: new {controller="Email", action="index"}
);

app.MapControllerRoute(
    name: "ChangePassword",
    pattern: "/change-password",
    defaults: new {controller="Email", action="ChangePassword"}
);

app.MapControllerRoute(
    name: "VerifyAccout",
    pattern: "/verify-accout",
    defaults: new {controller="Email", action="VerifyAccount"}
);

app.MapControllerRoute(
    name: "UserOrder",
    pattern: "/user-order",
    defaults: new {controller="Email", action="UserOrder"}
);

app.MapControllerRoute(
    name: "AdminNotifyOrder",
    pattern: "/admin-notify-order",
    defaults: new {controller="Email", action="AdminNotifyOrder"}
);

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseAuthentication();
app.UseAuthorization();  
app.MapControllers();

app.Run();
