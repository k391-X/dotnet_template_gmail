using FluentValidation;
using SmtpGmailDemo.Models;

namespace SmtpGmailDemo.Validators
{
    public class ResetPasswordViewModelValidator : AbstractValidator<ResetPasswordViewModel>
    {
        public ResetPasswordViewModelValidator()
        {
            RuleFor(x => x.Token)
                .NotEmpty().WithMessage("Thiếu mã token xác thực, vui lòng thử lại qua email.");

            RuleFor(x => x.NewPassword)
                .NotEmpty().WithMessage("Mật khẩu không được để trống")
                .MinimumLength(6).WithMessage("Mật khẩu phải ít nhất 6 ký tự");

            RuleFor(x => x.ConfirmPassword)
                .Equal(x => x.NewPassword)
                .WithMessage("Mật khẩu nhập lại không khớp");
        }
    }
}
