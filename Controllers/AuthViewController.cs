using Microsoft.AspNetCore.Mvc;
using SmtpGmailDemo.Models;

using SmtpGmailDemo.Services.Interfaces;
using SmtpGmailDemo.Utils;

namespace SmtpGmailDemo.Controllers
{
    public class AuthViewController : Controller
    {
        private readonly IAuthService _authService;

        public AuthViewController(IAuthService authService)
        {
            _authService = authService;
        }

        // Trang đăng nhập
        [HttpGet("/login")]
        public IActionResult Login()
        {
            return View("~/Views/AuthView/Login.cshtml");
        }

        // Trang đăng ký
        [HttpGet("/register")]
        public IActionResult Register()
        {
            return View();
        }

        [HttpPost("/register")]
        public async Task<IActionResult> Register(RegisterViewModel model)
        {
            // ✅ 1. FluentValidation sẽ tự chạy trước, nên ModelState đã có lỗi nếu invalid
            if (!ModelState.IsValid)
                return View(model); // hiển thị lại form với lỗi và dữ liệu cũ

            // ✅ 2. Gọi service đăng ký
            var registerModel = new Register
            {
                Email = model.Email,
                Password = model.Password,
                ConfirmPassword = model.ConfirmPassword
            };

            var result = await _authService.RegisterUserAsync(registerModel);

            // ✅ 3. Nếu đăng ký thất bại → thêm lỗi từ service vào ModelState
            if (!result.Succeeded)
            {
                // Gộp tất cả lỗi (hoặc chỉ lấy lỗi đầu tiên nếu muốn ngắn)
                foreach (var error in result.Errors)
                {
                    ModelState.AddModelError(string.Empty, error.Description);
                }

                return View(model);
            }

            // ✅ 4. Nếu thành công → chuyển hướng hoặc hiển thị thông báo thành công
            TempData["Success"] = "Đăng ký thành công! Vui lòng kiểm tra email xác nhận.";
            return View("~/Views/AuthView/RegisterConfirmation.cshtml");
        }  

        // View thông báo gửi email
        [HttpGet]
        public IActionResult RegisterConfirmation()
        {
            return View();
        }

        // Trang quên mật khẩu
        [HttpGet("/forgot-password")]
        public IActionResult ForgotPassword()
        {
            return View("~/Views/Auth/ForgotPassword.cshtml");
        }

        // Trang đặt lại mật khẩu
        [HttpGet("/reset-password")]
        public IActionResult ResetPassword(string email, string token)
        {
            ViewBag.Email = email;
            ViewBag.Token = token;
            return View("~/Views/Auth/ResetPassword.cshtml");
        }
    }
}
