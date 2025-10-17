using Microsoft.AspNetCore.Identity;

namespace SmtpGmailDemo.Models
{
    public class ApplicationUser : IdentityUser 
    {
        // Tự thêm các thuộc tính khác
        public string? FullName {get;set;}
    }
}