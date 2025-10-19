using System.Collections.Generic;
using System.Threading.Tasks;
using SmtpGmailDemo.Enums;

namespace SmtpGmailDemo.Services
{
    public interface IEmailTemplateService
    {
        /// <summary>
        /// Gửi email với template có sẵn theo loại
        /// </summary>
        /// <param name="type">Loại email (xác thực, đổi mật khẩu, hóa đơn,...)</param>
        /// <param name="to">Địa chỉ người nhận</param>
        /// <param name="placeholders">Các biến dùng trong template</param>
        /// <param name="fromName">Tên người gửi hiển thị</param>
        Task SendEmailAsync(EmailTemplateType type, string to, Dictionary<string, string> placeholders, string? fromName = null);
    }
}
