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
            // 1️⃣ Kiểm tra user đã tồn tại
            var existingUser = await _userManager.FindByEmailAsync(model.Email);
            Logger.Log("existingUser", existingUser);

            ApplicationUser user;
            bool isNewUser = false;

            if (existingUser != null)
            {
                // Nếu đã xác thực email → lỗi trùng email
                if (existingUser.EmailConfirmed)
                {
                    return IdentityResult.Failed(new IdentityError 
                    { 
                        Description = "Email đã tồn tại và đã được xác thực." 
                    });
                }

                // Chưa xác thực → chỉ dùng user cũ
                user = existingUser;

                // ❌ Xóa tất cả token VerifyEmail cũ trước khi tạo token mới
                var oldTokens = _context.CustomUserTokens
                    .Where(t => t.UserId == user.Id && t.TokenType == TokenType.VerifyEmail);
                _context.CustomUserTokens.RemoveRange(oldTokens);
                await _context.SaveChangesAsync();
            }
            else
            {
                // Nếu user chưa tồn tại → tạo mới
                user = new ApplicationUser
                {
                    UserName = model.Email,
                    Email = model.Email
                };

                var result = await _userManager.CreateAsync(user, model.Password);
                if (!result.Succeeded)
                    return result;

                isNewUser = true;
            }

            // 2️⃣ Sinh token xác thực mới
            var encryptedToken = await GenerateAndStoreTokenAsync(user);
            var encodedToken = Uri.EscapeDataString(encryptedToken);
            var confirmUrl = $"http://localhost:7042/verify?token={encodedToken}";

            // 3️⃣ Gửi email xác thực
            await SendForgotPasswordAsync(user, confirmUrl);

            // 4️⃣ Trả kết quả
            if (isNewUser)
                return IdentityResult.Success; // user mới đã tạo thành công
            else
                return IdentityResult.Failed(new IdentityError
                {
                    Description = "Email đã được đăng ký nhưng chưa xác thực. Email xác thực mới đã được gửi."
                });
        }

        // Phương thức gửi email xác thực
        private async Task SendVerificationEmailAsync(ApplicationUser user, string confirmUrl)
        {
            var placeholders = new Dictionary<string, string>
            {
                {"Name", user.Email.Split('@')[0]},
                {"Email", user.Email},
                {"LinkConfirm", confirmUrl},
                {"LifeTime", "30 phút"},
                {"NameCompany", "Tạp chí điện tử THT"}
            };

            await _emailTemplateService.SendEmailAsync(
                EmailTemplateType.VerifyAccount,
                user.Email,
                placeholders
            );
        }

        // Phương thức gửi email forgot password
        private async Task SendForgotPasswordAsync(ApplicationUser user, string confirmUrl)
        {
            var placeholders = new Dictionary<string, string>
            {
                {"Name", user.Email.Split('@')[0]},
                {"Email", user.Email},
                {"LinkConfirm", confirmUrl},
                {"LifeTime", "30 phút"},
                {"NameCompany", "Tạp chí điện tử THT"}
            };

            await _emailTemplateService.SendEmailAsync(
                EmailTemplateType.ChangePassword,
                user.Email,
                placeholders
            );
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

        // Tạo token mới , mã hóa, lưu vào db -- Đối với Verify Accounts
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

        // Tạo token mới , mã hóa, lưu vào db -- Đối với ForgotPassword
         private async Task<string> GenerateAndStoreTokenForgotPasswordAsync(ApplicationUser user)
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
                TokenType = TokenType.ResetPassword
            });

            await _context.SaveChangesAsync();
            return encryptedToken;
        }

        // Validate token
        public async Task<IdentityResult> ValidateStoredTokenAsync(string token, TokenType expectedType)
        {
            var dbToken = await _context.CustomUserTokens
                .FirstOrDefaultAsync(t =>
                    t.EncryptedToken == token &&
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

            // 2️⃣ So sánh token đã mã hóa
            if (dbToken.EncryptedToken != token)
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

        public async Task<IdentityResult> ConfirmEmailAsync(string encryptedToken)
        {
            try
            {
                // 1️⃣ Validate token (đảm bảo chưa hết hạn, đúng loại)
                var dbTokenResult = await ValidateStoredTokenAsync(encryptedToken, TokenType.VerifyEmail);

                Logger.Log("✅ Validate Result:", dbTokenResult.Succeeded ? "OK" : "FAILED");

                if (!dbTokenResult.Succeeded)
                {
                    foreach (var err in dbTokenResult.Errors)
                        Logger.Log("❌ Validate Error:", $"{err.Code} - {err.Description}");

                    return dbTokenResult;
                }

                // 2️⃣ Lấy token từ DB
                var dbToken = await _context.CustomUserTokens
                    .FirstOrDefaultAsync(t => t.EncryptedToken == encryptedToken);

                if (dbToken == null)
                    return IdentityResult.Failed(new IdentityError
                    {
                        Description = "Token không tồn tại trong DB."
                    });

                // 3️⃣ Lấy user liên quan
                var user = await _userManager.FindByIdAsync(dbToken.UserId);
                if (user == null)
                    return IdentityResult.Failed(new IdentityError
                    {
                        Description = "User không tồn tại."
                    });

                // 4️⃣ Cập nhật EmailConfirmed = true
                user.EmailConfirmed = true;
                await _userManager.UpdateAsync(user);

                // 5️⃣ Xóa token sau khi dùng
                _context.CustomUserTokens.Remove(dbToken);
                await _context.SaveChangesAsync();

                Logger.Log("✅ Email đã được xác thực thành công:", $"UserId={user.Id}");

                return IdentityResult.Success;
            }
            catch (Exception ex)
            {
                Logger.Log("🔥 Exception in ConfirmEmailAsync:", ex.Message);
                return IdentityResult.Failed(new IdentityError
                {
                    Description = "Lỗi hệ thống khi xác nhận email."
                });
            }
        }

        public async Task<string?> LoginAsync(Login model)
        {
            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null || !await _userManager.CheckPasswordAsync(user, model.Password)) return null;
            if (!user.EmailConfirmed) return null;

            return GenerateJwtToken(user);
        }

        public async Task<string?> ForgotPasswordAsync(ForgotPasswordViewModel model)
        {
            Logger.Log("ForgotPasswordAsync 1", model);
            var user = await _userManager.FindByEmailAsync(model.Email);
            Logger.Log("ForgotPasswordAsync 2", user);

            if (user == null) return null;

            // 2️⃣ Sinh token thay đổi mật khẩu mới
            var encryptedToken = await GenerateAndStoreTokenForgotPasswordAsync(user);
            Logger.Log("ForgotPasswordAsync 3", encryptedToken);

            var confirmUrl = $"http://localhost:7042/reset-password?email={model.Email}&token={encryptedToken}";

            // 3️⃣ Gửi email xác thực
            await SendVerificationEmailAsync(user, confirmUrl);
            Logger.Log("ForgotPasswordAsync 4");

            // Nếu thành công → trả về link reset (hoặc có thể trả về thông báo success)
            return confirmUrl;
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
