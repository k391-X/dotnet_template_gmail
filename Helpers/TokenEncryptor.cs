using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace SmtpGmailDemo.Helpers
{
    public static class TokenEncryptor
    {
        // Khóa bí mật AES, có thể là bất kỳ chuỗi nào
        private static readonly string secretKey = "MySuperStrongAESKey1234567890!!";

        // Chuyển secretKey thành 32 byte (256 bit) dùng SHA256
        private static byte[] GetAesKey()
        {
            using var sha = SHA256.Create();
            return sha.ComputeHash(Encoding.UTF8.GetBytes(secretKey));
        }

        // Mã hóa chuỗi
        public static string Encrypt(string plainText)
        {
            using var aes = Aes.Create();
            aes.Key = GetAesKey();
            aes.GenerateIV(); // tạo IV mới cho mỗi lần mã hóa

            using var ms = new MemoryStream();
            // Ghi IV vào đầu stream
            ms.Write(aes.IV, 0, aes.IV.Length);

            using (var cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
            using (var sw = new StreamWriter(cs))
            {
                sw.Write(plainText);
            }

            return Convert.ToBase64String(ms.ToArray());
        }

        // Giải mã chuỗi
        public static string Decrypt(string cipherText)
        {
            var fullCipher = Convert.FromBase64String(cipherText);

            using var aes = Aes.Create();
            aes.Key = GetAesKey();

            // Lấy IV từ 16 byte đầu
            var iv = new byte[16];
            Array.Copy(fullCipher, iv, iv.Length);
            aes.IV = iv;

            using var ms = new MemoryStream(fullCipher.AsSpan(16).ToArray());
            using var cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Read);
            using var sr = new StreamReader(cs);
            return sr.ReadToEnd();
        }
    }
}
