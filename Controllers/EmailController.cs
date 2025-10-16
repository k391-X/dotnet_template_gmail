using Microsoft.AspNetCore.Mvc;
using SmtpGmailDemo.Services;
using SmtpGmailDemo.Utils;

namespace SmtpGmailDemo.Controllers;

public class EmailController : ControllerBase
{
    private readonly EmailService _emailService;
    public EmailController(EmailService emailService) => _emailService = emailService;

    public async Task<IActionResult> SendTest()
    {
        var placeholders = new Dictionary<string, string>
        {
            {"Name", "Thang"},
            {"Token", "123456abcdef"}
        };

        // Build email HTML
        //string emailBodyHtml = EmailTemplateHelper.BuildEmail(
        //    bodyTemplateName: "verify-account",
        //    placeholders: placeholders
        //);

        // Build email HTML
        string emailBodyHtml = EmailTemplateHelper.BuildEmail(
            bodyTemplateName: "change-password",
            placeholders: placeholders
        );

        // Khai báo từng thông tin email rõ ràng
        // Gửi tới email này
        string recipientEmail = "cmthang2407@gmail.com";

        // Dòng chữ in đậm đầu tiên của email
        //string emailSubject = "Đăng kí tài khoản thành công";
        string emailSubject = "Yêu cầu đổi mật khẩu";


        //string emailBodyHtml = "<h2>Xin chào!</h2><p>Đây là email test gửi bằng Gmail SMTP.</p>";
        string senderName = "Công ty Công Nghệ THT";


        // Gọi service gửi email
        await _emailService.SendEmailAsync(
            to: recipientEmail,
            subject: emailSubject,
            htmlBody: emailBodyHtml,
            fromMailboxAddress: senderName
        );

        return Ok("✅ Đã gửi email thành công!");
    }
}
