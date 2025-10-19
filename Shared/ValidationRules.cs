namespace SmtpGmailDemo.Shared
{
    public static class ValidationRules
    {
        // Regex kiểm tra email
        public const string EmailPattern = @"^[^\s@]+@[^\s@]+\.[^\s@]+$";

        // Regex kiểm tra password: ít nhất 6 ký tự, có chữ hoa, chữ thường, số
        public const string PasswordPattern = @"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{6,}$";

        // Thông báo lỗi tiếng việt
        public static class Messages 
        {
            public const string EmailRequired = "Email không được để trống";
            public const string EmailInvalid = "Email không hợp lệ";
            public const string PasswordRequired = "Mật khẩu không được để trống";
            public const string PasswordInvalid = "Mật khẩu phải ít nhất 6 ký tự, có chữ hoa, có chữ thường và số";
            public const string ConfirmPasswordRequired = "Xác nhận mật khẩu không được để trống";
            public const string PasswordMismatch = "Mật khẩu xác nhận không trùng khớp";
        }
    }
}