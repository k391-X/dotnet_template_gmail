using System.ComponentModel.DataAnnotations;

namespace SmtpGmailDemo.Models
{
    public class RegisterViewModel
    {
        public string Email { get; set; } = null!;
        public string Password { get; set; } = null!;
        public string ConfirmPassword { get; set; } = null!;
    }
}
