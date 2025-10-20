using Microsoft.AspNetCore.Identity;
using SmtpGmailDemo.Models;

namespace SmtpGmailDemo.Services.Interfaces
{
    public interface IAuthService
    {
        Task<IdentityResult> RegisterUserAsync(Register model);
        Task<string?> LoginAsync(Login model);
        Task<string?> ForgotPasswordAsync(ForgotPasswordViewModel model);
        Task<IdentityResult> ResetPasswordAsync(ResetPasswordViewModel model);
        Task<IdentityResult> ConfirmEmailAsync(string encryptedToken);
    }
}
