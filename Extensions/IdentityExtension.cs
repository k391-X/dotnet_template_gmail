using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using SmtpGmailDemo.Data;
using SmtpGmailDemo.Models;

namespace SmtpGmailDemo.Extensions
{
    public static class IdentityExtension 
    {
        public static IServiceCollection AddAppIdentity(this IServiceCollection services, IConfiguration configuration) {

            // Kết nối SQL Server
            services.AddDbContext<ApplicationDbContext>(options => 
                options.UseSqlServer(configuration.GetConnectionString("DefaultConnection")));
            
            // Cấu hình Identity
            services.AddIdentity<ApplicationUser, IdentityRole>(options => {
                options.Password.RequireDigit = true;
                options.Password.RequireUppercase = false;
                options.Password.RequireLowercase = true;
                options.Password.RequireNonAlphanumeric = false;
                options.Password.RequiredLength = 6;
                options.User.RequireUniqueEmail = true;
            })
            .AddEntityFrameworkStores<ApplicationDbContext>()
            .AddDefaultTokenProviders();

            return services;
        }
    }
}