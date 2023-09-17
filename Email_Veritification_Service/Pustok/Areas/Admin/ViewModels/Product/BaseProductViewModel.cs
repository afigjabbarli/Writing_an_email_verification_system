using System.ComponentModel.DataAnnotations;

namespace Pustok.Areas.Admin.ViewModels.Product;

public abstract class BaseProductViewModel
{
    [Required]
    [StringLength(200, MinimumLength = 3)]
    public string Name { get; set; }

    [Required]
    public string Description { get; set; }

    [Required]
    public string Color { get; set; }

    [Required]
    public string Size { get; set; }

    [Required]
    public decimal Price { get; set; }
}
