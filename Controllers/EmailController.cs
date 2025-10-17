using Microsoft.AspNetCore.Mvc;
using SmtpGmailDemo.Services;
using SmtpGmailDemo.Utils;
using SmtpGmailDemo.Models;

namespace SmtpGmailDemo.Controllers;

public class EmailController : ControllerBase
{
    private readonly EmailService _emailService;
    public EmailController(EmailService emailService) => _emailService = emailService;

    public String index() {
        return "Route /change-password hoặc /verify-accounts";
    }

    public async Task<IActionResult> VerifyAccount()
    {
        var placeholders = new Dictionary<string, string>
        {
            {"Name", "Thang"},
            {"Email", "cmthang2407@gmail.com"},
            {"NameCompany", "Tạp chí điện tử Công ty Công nghệ THT"},
            {"LifeTime", "24 giờ"},
            {"Token", "123456abcdef"}
        };

        // Build email HTML
        string emailBodyHtml = EmailTemplateHelper.BuildEmail(
            bodyTemplateName: "verify-account",
            placeholders: placeholders
        );

        // Gửi tới email này
        string recipientEmail = "cmthang2407@gmail.com";

        // Dòng chữ in đậm đầu tiên của email
        string emailSubject = "Đăng kí tài khoản thành công";

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

    public async Task<IActionResult> ChangePassword()
    {
        var placeholders = new Dictionary<string, string>
        {
            {"Name", "Thang"},
            {"Email", "cmthang2407@gmail.com"},
            {"NameCompany", "Tạp chí điện tử Công ty Công nghệ THT"},
            {"LifeTime", "24 giờ"},
            {"Token", "123456abcdef"}
        };

        // Build email HTML
        string emailBodyHtml = EmailTemplateHelper.BuildEmail(
            bodyTemplateName: "change-password",
            placeholders: placeholders
        );

        // Gửi tới email này
        string recipientEmail = "cmthang2407@gmail.com";

        // Dòng chữ in đậm đầu tiên của email
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

    public async Task<IActionResult> UserOrder()
    {
        // Tạo danh sách các món hàng
        var items = new List<OrderItem> {
            new OrderItem { Index = 1, ItemName = "Laptop Dell", Unit = "Chiếc", Quantity = 1, Price = "15,000,000", Total = "15,000,000" },
            new OrderItem { Index = 2, ItemName = "Chuột Logitech", Unit = "Chiếc", Quantity = 2, Price = "500,000", Total = "1,000,000" },
        };

        // Tạo ViewModel hóa đơn
        var model = new UserOrderViewModel
        {
                CustomerName = "Thang",
                InvoiceDate = DateTime.Now.ToString("dd/MM/yyyy"),
                GrandTotal = "16,000,000",
                Items = items,        
        };

        // Build HTML các dòng item
        string itemRowsHtml = "";
        foreach (var item in items) {
            itemRowsHtml += $@"
                <tr>
                    <td>{item.Index}</td>
                    <td>{item.ItemName}</td>
                    <td>{item.Unit}</td>
                    <td>{item.Quantity}</td>
                    <td>{item.Price}đ</td>
                    <td>{item.Total}đ</td>
                </tr>
            ";
        };

        var placeholders = new Dictionary<string, string>
        {
            {"CustomerName", "Thang"},
            {"CompanyName", "Tạp chí điện tử Công ty Công nghệ THT"},
            {"InvoiceDate", DateTime.Now.ToString("dd/MM/yyyy HH:mm:ss")},
            {"GrandTotal", "16,000,000"},
            {"BillCode", "9kdjte82"},
            {"LinkHistoryBill", "example.com"},
            {"GmailSupport", "support@thtstore.com"},
            {"ItemRows", itemRowsHtml} // Đây là key dùng trong template
        };

        // Build email HTML
        string emailBodyHtml = EmailTemplateHelper.BuildEmail(
            bodyTemplateName: "user-order",
            placeholders: placeholders
        );

        // Gửi tới email này
        string recipientEmail = "cmthang2407@gmail.com";
        // Dòng chữ in đậm đầu tiên của email
        string emailSubject = "Thanh toán thành công!";
        // Người gửi
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

    public async Task<IActionResult> AdminOrderProcessing()
    {
        var placeholders = new Dictionary<string, string>
        {
            {"Name", "Thang"},
            {"Email", "cmthang2407@gmail.com"},
            {"Token", "123456abcdef"},
        };

        // Build email HTML
        string emailBodyHtml = EmailTemplateHelper.BuildEmail(
            bodyTemplateName: "change-password",
            placeholders: placeholders
        );

        // Gửi tới email này
        string recipientEmail = "cmthang2407@gmail.com";

        // Dòng chữ in đậm đầu tiên của email
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
