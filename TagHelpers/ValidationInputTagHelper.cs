using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.AspNetCore.Mvc.ViewFeatures;
using Microsoft.AspNetCore.Razor.TagHelpers;

namespace RazorValidationDemo.TagHelpers
{
    [HtmlTargetElement("input", Attributes = "asp-for")]
    public class ValidationInputTagHelper : TagHelper
    {
        [ViewContext]
        [HtmlAttributeNotBound]
        public ViewContext ViewContext { get; set; } = default!;

        [HtmlAttributeName("asp-for")]
        public ModelExpression For { get; set; } = default!;

        public override void Process(TagHelperContext context, TagHelperOutput output)
        {
            var fieldName = For.Name;
            var modelState = ViewContext.ViewData.ModelState;

            if (modelState.TryGetValue(fieldName, out var entry) &&
                entry.ValidationState == ModelValidationState.Invalid)
            {
                var existingClass = output.Attributes["class"]?.Value?.ToString();
                output.Attributes.SetAttribute("class", $"{existingClass} is-invalid".Trim());
            }
        }
    }
}
