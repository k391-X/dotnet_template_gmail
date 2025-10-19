using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using SmtpGmailDemo.Data;
using SmtpGmailDemo.Helpers;
using SmtpGmailDemo.Models;
using SmtpGmailDemo.Services.Interfaces;
using SmtpGmailDemo.Enums;

using SmtpGmailDemo.Utils;

namespace SmtpGmailDemo.Services.Implementations
{
    public class AuthService : IAuthService
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly ApplicationDbContext _context;
        private readonly IConfiguration _configuration;
        private readonly IEmailTemplateService _emailTemplateService;

        public AuthService(UserManager<ApplicationUser> userManager, ApplicationDbContext context, IConfiguration configuration, IEmailTemplateService emailTemplateService)
        {
            _userManager = userManager;
            _context = context;
            _configuration = configuration;
            _emailTemplateService = emailTemplateService;
        }

        public async Task<IdentityResult> RegisterUserAsync(Register model)
        {
            // Kiểm tra trùng email
            var existingUser = await _userManager.FindByEmailAsync(model.Email);
            if (existingUser != null)
            {
                return IdentityResult.Failed(new IdentityError { Description = "Email đã tồn tại" });
            }

            var user = new ApplicationUser
            {
                UserName = model.Email,
                Email = model.Email
            };

            // Tạo user mới
            var resultUser = await _userManager.CreateAsync(user, model.Password);
            if (!resultUser.Succeeded)
                return resultUser;

            // ✅ Sinh token xác thực, mã hóa, lưu db
            var encryptedToken = await GenerateAndStoreTokenAsync(user);
            
            // ✅ Tạo link xác thực
            var confirmUrl = $"{_configuration["AppSettings:FrontendUrl"]}/verify?email={user.Email}&token={encryptedToken}";

            // ✅ Gửi email xác thực qua EmailTemplateService
            var placeholders = new Dictionary<string, string>
            {
                {"Name", user.Email.Split('@')[0]},
                {"Email", user.Email},
                {"Token", encryptedToken},
                {"LinkConfirm", confirmUrl},
                {"LifeTime", "30 phút"},
                {"NameCompany", "Tạp chí điện tử THT"}
            };

            await _emailTemplateService.SendEmailAsync(
                EmailTemplateType.VerifyAccount,
                user.Email,
                placeholders
            );

            return resultUser;
        }

        // Kiểm tra đã tồn tại email
        private async Task<IdentityResult?> CheckExistingUserAsync(string email)
        {
            var existingUser = await _userManager.FindByEmailAsync(email);
            if (existingUser == null) return null;

            var error = existingUser.EmailConfirmed
                ? new IdentityError
                {
                    Code = "DuplicateEmail",
                    Description = "Email đã tồn tại."
                }
                : new IdentityError
                {
                    Code = "EmailNotConfirmed",
                    Description = "Email đã được đăng ký nhưng chưa xác nhận. Vui lòng kiểm tra hộp thư."
                };

            return IdentityResult.Failed(error);
        }

        // Tạo user mới
        private async Task<IdentityResult> CreateNewUserAsync(Register model)
        {
            var user = new ApplicationUser
            {
                UserName = model.Email,
                Email = model.Email
            };

            var result = await _userManager.CreateAsync(user, model.Password);

            if (!result.Succeeded)
            {
                foreach (var err in result.Errors)
                    Logger.Log($"Identity Error: {err.Description}");
            }

            return result;
        }

        // Xóa bỏ token cũ
        private async Task RemoveOldTokensAsync(string userId)
        {
            var oldTokens = _context.CustomUserTokens
                .Where(t => t.UserId == userId && t.TokenType == TokenType.VerifyEmail);

            _context.CustomUserTokens.RemoveRange(oldTokens);
            await _context.SaveChangesAsync();
        }

        // Tạo token mới , mã hóa, lưu vào db
        private async Task<string> GenerateAndStoreTokenAsync(ApplicationUser user)
        {
            var token = GenerateJwtToken(user);
            var encryptedToken = TokenEncryptor.Encrypt(token);
            var minuteLifeTimeToken = 30;

            _context.CustomUserTokens.Add(new CustomUserToken
            {
                UserId = user.Id,
                OriginalToken = token,
                EncryptedToken = encryptedToken,
                CreatedAt = DateTime.UtcNow,
                IsUsed = false,
                ExpiresAt = DateTime.UtcNow.AddMinutes(minuteLifeTimeToken),
                TokenType = TokenType.VerifyEmail
            });

            await _context.SaveChangesAsync();
            return encryptedToken;
        }

        // Validate token
        public async Task<IdentityResult> ValidateStoredTokenAsync(string userId, string token, TokenType expectedType)
        {
            var dbToken = await _context.CustomUserTokens
                .FirstOrDefaultAsync(t =>
                    t.UserId == userId &&
                    t.TokenType == expectedType);

            if (dbToken == null)
            {
                return IdentityResult.Failed(new IdentityError
                {
                    Code = "TokenNotFound",
                    Description = "Token không tồn tại hoặc đã bị thu hồi."
                });
            }

            // 1️⃣ Token hết hạn => xóa luôn
            if (dbToken.ExpiresAt < DateTime.UtcNow)
            {
                _context.CustomUserTokens.Remove(dbToken);
                await _context.SaveChangesAsync();

                return IdentityResult.Failed(new IdentityError
                {
                    Code = "TokenExpired",
                    Description = "Token đã hết hạn. Vui lòng yêu cầu token mới."
                });
            }

            // 2️⃣ So sánh token gốc (chưa mã hóa)
            if (dbToken.OriginalToken != token)
            {
                return IdentityResult.Failed(new IdentityError
                {
                    Code = "TokenInvalid",
                    Description = "Token không hợp lệ hoặc đã bị thay đổi."
                });
            }

            return IdentityResult.Success;
        }

        // Xóa bỏ token sau khi sử dụng
        public async Task RemoveTokenAsync(string userId, string token)
        {
            var dbToken = await _context.CustomUserTokens
                .FirstOrDefaultAsync(t => t.UserId == userId && t.OriginalToken == token);

            if (dbToken != null)
            {
                _context.CustomUserTokens.Remove(dbToken);
                await _context.SaveChangesAsync();
            }
        }

        // Gửi gmail hoàn tất xác nhận
        private async Task SendVerificationEmailAsync(ApplicationUser user, string token)
        {
            var encodedToken = Uri.EscapeDataString(token);
            var confirmUrl = $"{_configuration["AppSettings:FrontendUrl"]}/verify?email={user.Email}&token={encodedToken}";

            var placeholders = new Dictionary<string, string>
            {
                {"Name", user.Email.Split('@')[0]},
                {"Email", user.Email},
                {"Token", token},
                {"LinkConfirm", confirmUrl},
                {"LifeTime", "24 giờ"}
            };

            await _emailTemplateService.SendEmailAsync(
                EmailTemplateType.VerifyAccount,
                user.Email,
                placeholders
            );
        }

        public async Task<string?> LoginAsync(Login model)
        {
            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null || !await _userManager.CheckPasswordAsync(user, model.Password)) return null;
            if (!user.EmailConfirmed) return null;

            return GenerateJwtToken(user);
        }

        public async Task<string?> ForgotPasswordAsync(ForgotPassword model)
        {
            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null) return null;

            var token = await _userManager.GeneratePasswordResetTokenAsync(user);
            var encodedToken = System.Net.WebUtility.UrlEncode(token);

            var resetLink = $"https://localhost:7042/reset-password?email={model.Email}&token={encodedToken}";
            Console.WriteLine($"Reset Password Link: {resetLink}");
            return resetLink;
        }

        public async Task<IdentityResult> ResetPasswordAsync(ResetPassword model)
        {
            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null) return IdentityResult.Failed(new IdentityError { Description = "User not found" });

            var decodedToken = System.Net.WebUtility.UrlDecode(model.Token);
            return await _userManager.ResetPasswordAsync(user, decodedToken, model.NewPassword);
        }

        private string GenerateJwtToken(ApplicationUser user)
        {
            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.Email!),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(ClaimTypes.NameIdentifier, user.Id)
            };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]!));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: _configuration["Jwt:Issuer"],
                audience: _configuration["Jwt:Audience"],
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(30),
                signingCredentials: creds
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }
}
