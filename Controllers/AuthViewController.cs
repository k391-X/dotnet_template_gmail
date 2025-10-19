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
            return View("~/Views/Auth/Login.cshtml");
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
            if (!ModelState.IsValid)
                return View(model);

            var registerModel = new Register
            {
                Email = model.Email,
                Password = model.Password,
                ConfirmPassword = model.ConfirmPassword
            };

            var result = await _authService.RegisterUserAsync(registerModel);

            if (!result.Succeeded)
            {
                // Chỉ lấy lỗi đầu tiên để hiển thị
                ModelState.AddModelError(string.Empty, result.Errors.First().Description);
                return View(model);
            }

            // Nếu thành công, redirect sang view thông báo gửi email
            return RedirectToAction("RegisterConfirmation");
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
