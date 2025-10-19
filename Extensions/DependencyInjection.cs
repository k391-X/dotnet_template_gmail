using FluentValidation;
using FluentValidation.AspNetCore;
using Microsoft.Extensions.DependencyInjection;

namespace SmtpGmailDemo.Extensions
{
    public static class DependencyInjection
    {
        public static IServiceCollection AddAppServices(this IServiceCollection services)
        {
            services.AddControllersWithViews()
                .AddFluentValidation(fv =>
                    fv.RegisterValidatorsFromAssemblyContaining<Program>());

            // Kích hoạt tự động validation backend + client
            services.AddFluentValidationAutoValidation();
            services.AddFluentValidationClientsideAdapters();

            return services;
        }
    }
}
