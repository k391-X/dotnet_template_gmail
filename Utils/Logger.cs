using System;
using System.IO;
using System.Runtime.CompilerServices;

namespace SmtpGmailDemo.Utils
{
    public static class Logger
    {
        // File log ở root project
        private static readonly string logFilePath = Path.Combine(Directory.GetCurrentDirectory(), "log.txt");

        /// <summary>
        /// Ghi log ra file + console
        /// </summary>
        /// <param name="message">Nội dung chính</param>
        /// <param name="custom">Chuỗi custom (ví dụ a từ config)</param>
        /// <param name="file">Tên file gọi log (tự động)</param>
        /// <param name="line">Số dòng gọi log (tự động)</param>
        public static void Log(
            string message,
            string? custom = null,
            [CallerFilePath] string file = "",
            [CallerLineNumber] int line = 0
        )
        {
            string timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
            string logEntry = $"[{timestamp}] [{Path.GetFileName(file)}:{line}] {message}";
            if (!string.IsNullOrEmpty(custom))
            {
                logEntry += $" | {custom}";
            }

            // In ra console
            Console.WriteLine(logEntry);

            // Append ra file log
            try
            {
                File.AppendAllText(logFilePath, logEntry + Environment.NewLine);
            }
            catch
            {
                // Nếu ghi file lỗi thì bỏ qua, không crash app
            }
        }
    }
}
