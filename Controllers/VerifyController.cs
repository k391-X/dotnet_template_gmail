using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Identity;
using SmtpGmailDemo.Data;
using SmtpGmailDemo.Helpers;
using SmtpGmailDemo.Models;

namespace SmtpGmailDemo.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class VerifyController : ControllerBase
    {
        private readonly ApplicationDbContext _context;
        private readonly UserManager<ApplicationUser> _userManager;

        public VerifyController(ApplicationDbContext context, UserManager<ApplicationUser> userManager)
        {
            _context = context;
            _userManager = userManager;
        }

        /// <summary>
        /// Xác minh email người dùng (Verify Email)
        /// GET /api/verify?token=xxxx
        /// </summary>
        [HttpGet]
        public async Task<IActionResult> VerifyEmail([FromQuery] string token) 
        {
            if (string.IsNullOrEmpty(token))
                return BadRequest(new { message = "Thiếu token."});

            string decryptedToken;
            try {
                decryptedToken = TokenEncryptor.Decrypt(token);
            }
            catch {
                return BadRequest(new {message = "Token không hợp lệ hoặc đã bị thay đổi."});
            }

            // Tìm token gốc trong DB
            var tokenEntry = _context.CustomUserTokens.FirstOrDefault(t => t.OriginalToken == decryptedToken);
            if (tokenEntry == null)
                return NotFound(new {message = "Token không tồn tại hoặc đã được sử dụng."});

            // Kiểm tra hạn sử dụng
            if (tokenEntry.ExpiresAt < DateTime.UtcNow)
                return BadRequest(new {message = "Token đã hết hạn."});

            // Lấy user tương ứng
            var user = await _userManager.FindByIdAsync(tokenEntry.UserId);
            if (user == null)
                return NotFound(new {message = "không tìm thấy người dùng."});
        
            // Đánh dấu email đã xác thực
            user.EmailConfirmed = true;
            await _userManager.UpdateAsync(user);

            // Xóa token sau khi dùng (chỉ dùng 1 lần)
            _context.CustomUserTokens.Remove(tokenEntry);
            await _context.SaveChangesAsync();

            return Ok(new 
            {
                message = "Xác thực email thành công!",
                email = user.Email
            });

        }
    }
}