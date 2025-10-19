using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using SmtpGmailDemo.Enums;

namespace SmtpGmailDemo.Models
{
    public class CustomUserToken
    {
        [Key]
        public int? Id {get;set;}

        public string? UserId {get;set;}

        public string? OriginalToken {get;set;}

        public string? EncryptedToken {get;set;}

        public DateTime CreatedAt {get;set;} = DateTime.UtcNow;

        public bool IsUsed { get; set; } = false;
        public DateTime? ExpiresAt { get; set; }

        [ForeignKey("UserId")]
        public ApplicationUser? User {get;set;}

        public TokenType TokenType { get; set; } = TokenType.VerifyEmail;    
    }
}