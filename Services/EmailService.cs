using MailKit.Net.Smtp;
using MimeKit;
using Microsoft.Extensions.Options;
using SmtpGmailDemo.Utils;

namespace SmtpGmailDemo.Services
{
    public class EmailSettings
    {
        public string SmtpServer { get; set; } = "";
        public int Port { get; set; }
        public string From { get; set; } = "";
        public string AppPassword { get; set; } = "";
    }

    public class EmailService
    {
        private readonly EmailSettings _settings;

        public EmailService(IOptions<EmailSettings> options)
        {
            _settings = options.Value;
        }

        public async Task SendEmailAsync(string to, string subject, string htmlBody, string fromMailboxAddress)
        {
            var message = new MimeMessage();
            message.From.Add(new MailboxAddress(fromMailboxAddress, _settings.From));
            message.To.Add(MailboxAddress.Parse(to));
            message.Subject = subject;

            message.Body = new TextPart("html") { Text = htmlBody };

            using var client = new SmtpClient();
            await client.ConnectAsync(_settings.SmtpServer, _settings.Port, MailKit.Security.SecureSocketOptions.StartTls);
            await client.AuthenticateAsync(_settings.From, _settings.AppPassword);
            await client.SendAsync(message);
            await client.DisconnectAsync(true);
        }
    }
}
