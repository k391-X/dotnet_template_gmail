using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;

using SmtpGmailDemo.Enums;
using SmtpGmailDemo.Models;

namespace SmtpGmailDemo.Data
{
    public class ApplicationDbContext : IdentityDbContext<ApplicationUser>
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
            : base(options)
        {
        }

        // Thêm DBSet<> khác nếu cần
        public DbSet<CustomUserToken> CustomUserTokens {get;set;}

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);

            // Thiết lập quan hệ giữa User và Token
            builder.Entity<CustomUserToken>()
                .HasOne(t => t.User)
                .WithMany()
                .HasForeignKey(t => t.UserId)
                .OnDelete(DeleteBehavior.Cascade);

            // Tạo chỉ mục để truy vấn nhanh hơn
            builder.Entity<CustomUserToken>()
                .HasIndex(t => new { t.UserId, t.TokenType });

            // Gán giá trị mặc định cho TokenType
            builder.Entity<CustomUserToken>()
                .Property(t => t.TokenType)
                .HasDefaultValue(TokenType.VerifyEmail);
        }
    }
}
