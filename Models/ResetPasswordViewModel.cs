namespace SmtpGmailDemo.Models
{
    public class ResetPasswordViewModel
    {
        public string Token { get; set; } = string.Empty;

        public string NewPassword { get; set; } = string.Empty;
        public string ConfirmPassword { get; set; } = string.Empty;    
    }
}
