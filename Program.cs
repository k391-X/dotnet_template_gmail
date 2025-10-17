using SmtpGmailDemo.Services;
using SmtpGmailDemo.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

// 🟢 Cấu hình database (SQL Server)
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

// 🟢 Cấu hình Identity
builder.Services.AddIdentity<IdentityUser, IdentityRole>(options =>
{
    options.Password.RequireDigit = true;
    options.Password.RequireLowercase = true;
    options.Password.RequireUppercase = false;
    options.Password.RequiredLength = 6;
})
.AddEntityFrameworkStores<ApplicationDbContext>()
.AddDefaultTokenProviders();

// 🟢 Cấu hình email
builder.Services.Configure<EmailSettings>(
    builder.Configuration.GetSection("EmailSettings")
);

builder.Services.AddScoped<EmailService>();
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

// Xử lý phần Token
// builder.Services.AddScoped<TokenUtils>();

var app = builder.Build();

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
    name: "AdminOrderProcessing",
    pattern: "/admin-order-processing",
    defaults: new {controller="Email", action="AdminOrderProcessing"}
);

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseRouting();
app.UseAuthentication(); // thêm dòng này
app.UseAuthorization();  // và dòng này

app.MapControllers();

app.Run();
