using Microsoft.AspNetCore.Identity;
using SmtpGmailDemo.Data;
using SmtpGmailDemo.Helpers;
using SmtpGmailDemo.Models;

namespace SmtpGmailDemo.Services
{
    public class EmailConfirmationService
    {
        private readonly ApplicationDbContext _context;
        private readonly UserManager<ApplicationUser> _userManager;

        public EmailConfirmationService(ApplicationDbContext context, UserManager<ApplicationUser> userManager)
        {
            _context = context;
            _userManager = userManager;
        }

        public async Task<(bool Success, string Message)> ConfirmEmailAsync(string email, string encryptedToken)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user == null)
                return (false, "User not found.");

            var tokenEntry = _context.CustomUserTokens.FirstOrDefault(t => t.UserId == user.Id);
            if (tokenEntry == null)
                return (false, "Token not found.");

            string originalToken;
            try
            {
                originalToken = TokenEncryptor.Decrypt(encryptedToken);
            }
            catch
            {
                return (false, "Invalid token format.");
            }

            if (tokenEntry.OriginalToken != originalToken)
                return (false, "Invalid token.");

            if (tokenEntry.ExpiresAt < DateTime.UtcNow)
                return (false, "Token expired.");

            user.EmailConfirmed = true;
            await _userManager.UpdateAsync(user);

            // Xóa token để tránh dùng lại
            _context.CustomUserTokens.Remove(tokenEntry);
            await _context.SaveChangesAsync();

            return (true, "Email confirmed successfully!");
        }
    }
}
