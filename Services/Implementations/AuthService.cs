using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using SmtpGmailDemo.Data;
using SmtpGmailDemo.Helpers;
using SmtpGmailDemo.Models;
using SmtpGmailDemo.Services.Interfaces;

using SmtpGmailDemo.Utils;

namespace SmtpGmailDemo.Services.Implementations
{
    public class AuthService : IAuthService
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly ApplicationDbContext _context;
        private readonly IConfiguration _configuration;

        public AuthService(UserManager<ApplicationUser> userManager, ApplicationDbContext context, IConfiguration configuration)
        {
            _userManager = userManager;
            _context = context;
            _configuration = configuration;
        }

        public async Task<IdentityResult> RegisterUserAsync(Register model)
        {
            // Log thông tin user (mask password)
            Logger.Log("Register attempt", new
            {
                model.Email,
                Password = "****",
                model.ConfirmPassword
            });

            // 1️⃣ Kiểm tra user tồn tại
            var existingUser = await _userManager.FindByEmailAsync(model.Email);
            if (existingUser != null)
            {
                if (!existingUser.EmailConfirmed)
                {
                    return IdentityResult.Failed(new IdentityError
                    {
                        Code = "EmailNotConfirmed",
                        Description = "Email đã được đăng ký nhưng chưa xác nhận. Vui lòng kiểm tra hộp thư."
                    });
                }
                else
                {
                    return IdentityResult.Failed(new IdentityError
                    {
                        Code = "DuplicateEmail",
                        Description = "Email đã tồn tại."
                    });
                }
            }

            // 2️⃣ Kiểm tra confirm password
            if (model.Password != model.ConfirmPassword)
            {
                return IdentityResult.Failed(new IdentityError
                {
                    Code = "PasswordMismatch",
                    Description = "Mật khẩu xác nhận không trùng khớp."
                });
            }

            // 3️⃣ Tạo user mới
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
                return result;
            }

            // 4️⃣ Xóa token cũ nếu có
            var oldTokens = _context.CustomUserTokens.Where(t => t.UserId == user.Id);
            _context.CustomUserTokens.RemoveRange(oldTokens);
            await _context.SaveChangesAsync();

            // 5️⃣ Tạo token JWT và lưu
            var token = GenerateJwtToken(user);
            var encryptedToken = TokenEncryptor.Encrypt(token);

            _context.CustomUserTokens.Add(new CustomUserToken
            {
                UserId = user.Id,
                OriginalToken = token,
                EncryptedToken = encryptedToken,
                CreatedAt = DateTime.UtcNow,
                IsUsed = false,
                ExpiresAt = DateTime.UtcNow.AddMinutes(30)
            });

            await _context.SaveChangesAsync();

            return IdentityResult.Success;
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
