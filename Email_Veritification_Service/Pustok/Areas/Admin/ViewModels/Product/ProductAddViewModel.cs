using System.ComponentModel.DataAnnotations;

namespace Pustok.Areas.Admin.ViewModels.Product;

public class ProductAddViewModel
{
    [Required]
    [StringLength(200, MinimumLength = 3)]
    public string Name { get; set; }

    [Required]
    public string Description { get; set; }

    [Required]
    public decimal Price { get; set; }

    [Required]
    public int[] CategoryIds { get; set; }
    public List<Database.Models.Category> Categories { get; set; }

    [Required]
    public int[] SizeIds { get; set; }
    public List<Database.Models.Size> Sizes { get; set; }

    [Required]
    public int[] ColorIds { get; set; }
    public List<Database.Models.Color> Colors { get; set; }

    public IFormFile Image { get; set; }
}
