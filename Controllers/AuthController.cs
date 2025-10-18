using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

using Microsoft.AspNetCore.RateLimiting;

using SmtpGmailDemo.Models;
using SmtpGmailDemo.Helpers;
using SmtpGmailDemo.Data;

namespace SmtpGmailDemo.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IConfiguration _configuration;
        private readonly ApplicationDbContext _context;

        public AuthController(ApplicationDbContext context, UserManager<ApplicationUser> userManager, IConfiguration configuration)
        {
            _context = context;
            _userManager = userManager;
            _configuration = configuration;
        }

        // Đăng ký tài khoản mới
        [EnableRateLimiting("registerLimiter")] // Gắn policy đã tạo
        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] Register model)
        {
            // Tạo user mới
            var user = new ApplicationUser
            {
                UserName = model.Email,
                Email = model.Email
            };

            var result = await _userManager.CreateAsync(user, model.Password);

            if (!result.Succeeded)
                return BadRequest(result.Errors);

            // Xóa các token cũ (nếu có - Chỉ có 1 token duy nhất để xác thực)
            var oldTokens = _context.CustomUserTokens.Where(t => t.UserId == user.Id);
            _context.CustomUserTokens.RemoveRange(oldTokens);
            await _context.SaveChangesAsync();

            // Bổ sung phần gửi trả lại token 
            // 2️⃣ Tạo JWT token gốc
            var token = GenerateJwtToken(user);

            // 3️⃣ Mã hóa token bằng AES
            var encryptedToken = TokenEncryptor.Encrypt(token);

            // 4️⃣ Lưu token gốc + mã hóa vào DB
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

            // 5️⃣ Trả token mã hóa về client
            return Ok(new
            {
                message = "User registered successfully!",
                token = encryptedToken
            });

        }

        // Đăng nhập và sinh JWT token
        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] Login model)
        {
            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null || !await _userManager.CheckPasswordAsync(user, model.Password))
                return Unauthorized(new { message = "Invalid email or password." });

            // 🔒 Kiểm tra xem email đã được xác thực chưa
            if (!user.EmailConfirmed)
                return Unauthorized(new { message = "Email has not been confirmed. Please verify your email before logging in." });

            var token = GenerateJwtToken(user);
            return Ok(new { token });
        }

        // 1️⃣ Quên mật khẩu - Gửi token đặt lại mật khẩu qua email
        [HttpPost("forgot-password")]
        [EnableRateLimiting("forgotPasswordLimiter")] // Gắn policy đã tạo
        public async Task<IActionResult> ForgotPassword([FromBody] ForgotPassword model)
        {
            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null)
                return BadRequest(new { message = "User not found" });

            var token = await _userManager.GeneratePasswordResetTokenAsync(user);
            var encodedToken = System.Net.WebUtility.UrlEncode(token);

            // ⚠️ Thay phần này bằng EmailService thực tế (hiện chỉ log ra console để test)
            var resetLink = $"https://localhost:7042/api/auth/reset-password?email={model.Email}&token={encodedToken}";
            Console.WriteLine($"Reset Password Link: {resetLink}");

            return Ok(new { message = "Password reset link generated successfully", link = resetLink });
        }

        // 2️⃣ Đặt lại mật khẩu
        [HttpPost("reset-password")]
        [EnableRateLimiting("resetPasswordLimiter")] // Gắn policy đã tạo
        public async Task<IActionResult> ResetPassword([FromBody] ResetPassword model)
        {
            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null)
                return BadRequest(new { message = "User not found" });

            // Giải mã token URL
            var decodedToken = System.Net.WebUtility.UrlDecode(model.Token);

            var result = await _userManager.ResetPasswordAsync(user, decodedToken, model.NewPassword);

            if (!result.Succeeded)
                return BadRequest(new { message = "Invalid token or password", errors = result.Errors });

            return Ok(new { message = "Password has been reset successfully!" });
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
