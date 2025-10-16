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
        // Khai báo từng thông tin email rõ ràng
        string recipientEmail = "cmthang2407@gmail.com";
        string emailSubject = "Test gửi email từ .NET";
        //string emailBodyHtml = "<h2>Xin chào!</h2><p>Đây là email test gửi bằng Gmail SMTP.</p>";
        string senderName = "From Thang Dep Trai";

        // Load template và replace biến
        string emailBodyHtml = EmailTemplateHelper.LoadTemplate(
            "verify-account",
            new Dictionary<string, string>
            {
                { "Name", "Thang" }
            }
        );

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
