using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

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
        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterModel model)
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
        public async Task<IActionResult> Login([FromBody] LoginModel model)
        {
            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null || !await _userManager.CheckPasswordAsync(user, model.Password))
                return Unauthorized(new { message = "Invalid email or password." });

            var token = GenerateJwtToken(user);
            return Ok(new { token });
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

        // Mô hình dữ liệu cho Register / Login
        public class RegisterModel
        {
            public string Email { get; set; } = string.Empty;
            public string Password { get; set; } = string.Empty;
        }

        public class LoginModel
        {
            public string Email { get; set; } = string.Empty;
            public string Password { get; set; } = string.Empty;
        }
    }
}
