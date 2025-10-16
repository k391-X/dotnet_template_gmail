using System.IO;

namespace SmtpGmailDemo.Utils;

public static class EmailTemplateHelper
{
    public static string LoadTemplate(string templateName, Dictionary<string, string>? placeholders = null)
    {
        string path = Path.Combine(Directory.GetCurrentDirectory(), "EmailTemplates", templateName + ".html");

        if (!File.Exists(path))
            throw new FileNotFoundException($"Template {templateName} not found at {path}");

        string content = File.ReadAllText(path);

        if (placeholders != null)
        {
            foreach (var kvp in placeholders)
            {
                content = content.Replace($"{{{{{kvp.Key}}}}}", kvp.Value);
            }
        }

        return content;
    }
}
