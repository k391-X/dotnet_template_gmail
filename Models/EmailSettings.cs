namespace SmtpGmailDemo.Models
{
    public class EmailSettings
    {
        public string SmtpServer { get; set; } = "smtp.gmail.com";
        public int Port { get; set; } = 587;
        public string? FromEmail { get; set; }
        public string? AppPassword { get; set; }
        public string? DisplayName { get; set; }
        public bool UseStartTls { get; set; } = true;
    }
}
