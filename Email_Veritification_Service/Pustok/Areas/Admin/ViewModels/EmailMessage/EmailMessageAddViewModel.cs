using System.ComponentModel.DataAnnotations;

namespace Pustok.Areas.Admin.ViewModels.EmailMessage;

public class EmailMessageAddViewModel
{
    [Required]
    public string Subject { get; set; }

    [Required]
    public string Content { get; set; }

    [Required]
    public string Receipents { get; set; }
}
