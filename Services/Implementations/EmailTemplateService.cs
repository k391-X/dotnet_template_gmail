using SmtpGmailDemo.Utils;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using SmtpGmailDemo.Enums;

namespace SmtpGmailDemo.Services
{
    public class EmailTemplateService : IEmailTemplateService
    {
        private readonly EmailService _emailService;

        public EmailTemplateService(EmailService emailService)
        {
            _emailService = emailService;
        }

        public async Task SendEmailAsync(EmailTemplateType type, string to, Dictionary<string, string> placeholders, string? fromName = null)
        {
            string templateName = GetTemplateFileName(type);
            string subject = GetSubject(type);
            string senderName = fromName ?? "Công ty Công Nghệ THT";

            // Tạo nội dung email HTML từ template
            string emailBodyHtml = EmailTemplateHelper.BuildEmail(
                bodyTemplateName: templateName,
                placeholders: placeholders
            );

            // Gửi mail
            await _emailService.SendEmailAsync(
                to: to,
                subject: subject,
                htmlBody: emailBodyHtml,
                fromMailboxAddress: senderName
            );

            return;
        }

        private static string GetTemplateFileName(EmailTemplateType type)
        {
            return type switch
            {
                EmailTemplateType.VerifyAccount => "verify-account",
                EmailTemplateType.ChangePassword => "change-password",
                EmailTemplateType.UserOrder => "user-order",
                EmailTemplateType.AdminNotifyOrder => "admin-notify-order",
                _ => throw new ArgumentOutOfRangeException(nameof(type), type, "Unknown email type")
            };
        }

        private static string GetSubject(EmailTemplateType type)
        {
            return type switch
            {
                EmailTemplateType.VerifyAccount => "Xác nhận đăng ký tài khoản",
                EmailTemplateType.ChangePassword => "Yêu cầu đổi mật khẩu",
                EmailTemplateType.UserOrder => "Thanh toán thành công!",
                EmailTemplateType.AdminNotifyOrder => "Đơn hàng mới từ khách hàng",
                _ => "Thông báo từ Công ty Công Nghệ THT"
            };
        }
    }
}
