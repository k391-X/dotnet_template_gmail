using System.IO;

namespace SmtpGmailDemo.Utils;

public static class EmailTemplateHelper
{
    /// <summary>
    /// Tạo email hoàn chỉnh với header + body + footer
    /// </summary>
    /// <param name="bodyTemplateName">Tên file body trong EmailTemplates (không kèm .html)</param>
    /// <param name="placeholders">Các biến để replace, ví dụ {{Name}}, {{Token}}</param>
    /// <returns>HTML hoàn chỉnh</returns>
    public static string BuildEmail(string bodyTemplateName, Dictionary<string, string>? placeholders = null)
    {
        string basePath = Path.Combine(Directory.GetCurrentDirectory(), "EmailTemplates");

        // Load header
        string headerPath = Path.Combine(basePath, "components", "Header.html");
        string header = File.Exists(headerPath) ? File.ReadAllText(headerPath) : "";

        // Load footer
        string footerPath = Path.Combine(basePath, "components", "Footer.html");
        string footer = File.Exists(footerPath) ? File.ReadAllText(footerPath) : "";

        // Load body
        string bodyPath = Path.Combine(basePath, bodyTemplateName + ".html");
        if (!File.Exists(bodyPath))
            throw new FileNotFoundException($"Template {bodyTemplateName} not found at {bodyPath}");
        string body = File.ReadAllText(bodyPath);

        // Thay placeholders trong body
        if (placeholders != null)
        {
            foreach (var kvp in placeholders)
            {
                body = body.Replace($"{{{{{kvp.Key}}}}}", kvp.Value);
            }
        }

        // Ghép header + body + footer
        return header + body + footer;
    }
}
