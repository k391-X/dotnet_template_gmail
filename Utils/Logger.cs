using System;
using System.IO;
using System.Runtime.CompilerServices;
using System.Text.Json;

namespace SmtpGmailDemo.Utils
{
    public static class Logger
    {
        // Thư mục Logs + file log
        private static readonly string logDirectory = Path.Combine(Directory.GetCurrentDirectory(), "Logs");
        private static readonly string logFilePath = Path.Combine(logDirectory, "log.txt");

        /// <summary>
        /// Ghi log ra console và file. Hỗ trợ object tự động serialize. 
        /// Nếu object có property tên "Password", "Token" sẽ được ẩn.
        /// </summary>
        /// <param name="message">Nội dung chính</param>
        /// <param name="custom">Chuỗi custom hoặc object bất kỳ</param>
        /// <param name="file">Tên file gọi log (tự động)</param>
        /// <param name="line">Số dòng gọi log (tự động)</param>
        public static void Log(
            string message,
            object? custom = null,
            [CallerFilePath] string file = "",
            [CallerLineNumber] int line = 0
        )
        {
            try
            {
                // Tạo folder Logs nếu chưa có
                if (!Directory.Exists(logDirectory))
                    Directory.CreateDirectory(logDirectory);

                string timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
                string logEntry = $"[{timestamp}] [{Path.GetFileName(file)}:{line}] {message}";

                if (custom != null)
                {
                    string customStr;

                    if (custom is string s)
                    {
                        customStr = s;
                    }
                    else
                    {
                        // Serialize object, ẩn Password/Token nếu có
                        var options = new JsonSerializerOptions
                        {
                            WriteIndented = true,
                            DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
                        };

                        var sanitized = SanitizeObject(custom);
                        customStr = JsonSerializer.Serialize(sanitized, options);
                    }

                    logEntry += $" | {customStr}";
                }

                // Ghi ra console
                Console.WriteLine(logEntry);

                // Ghi vào file
                File.AppendAllText(logFilePath, logEntry + Environment.NewLine);
            }
            catch (Exception ex)
            {
                // Nếu ghi file lỗi vẫn log ra console
                Console.WriteLine($"Logger error: {ex.Message}");
            }
        }

        /// <summary>
        /// Tạo bản sao object, ẩn các property nhạy cảm
        /// </summary>
        private static object SanitizeObject(object obj)
        {
            var type = obj.GetType();
            var copy = Activator.CreateInstance(type)!;

            foreach (var prop in type.GetProperties())
            {
                try
                {
                    var value = prop.GetValue(obj);

                    if (prop.Name.Equals("Password", StringComparison.OrdinalIgnoreCase) ||
                        prop.Name.Equals("Token", StringComparison.OrdinalIgnoreCase) ||
                        prop.Name.Equals("Secret", StringComparison.OrdinalIgnoreCase))
                    {
                        prop.SetValue(copy, "****");
                    }
                    else
                    {
                        prop.SetValue(copy, value);
                    }
                }
                catch
                {
                    // Ignore property không set được
                }
            }

            return copy;
        }
    }
}
