namespace Pustok.Areas.Admin.ViewModels.Product;

public class ProductUpdateViewModel : BaseProductViewModel
{
    public int Id { get; set; }
    public int[] CategoryIds { get; set; }
    public List<Database.Models.Category> Categories { get; set; }

    public IFormFile Image { get; set; }
    public string CurrentFileName { get; set; }
}
