using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace SmtpGmailDemo.Models
{
    public class CustomUserToken
    {
        [Key]
        public int? Id {get;set;}

        [Required]
        public string? UserId {get;set;}

        public string? OriginalToken {get;set;}

        [Required]
        public string? EncryptedToken {get;set;}

        public DateTime CreatedAt {get;set;} = DateTime.UtcNow;

        public bool IsUsed { get; set; } = false;
        public DateTime? ExpiresAt { get; set; }

        [ForeignKey("UserId")]
        public ApplicationUser? User {get;set;}
    }
}