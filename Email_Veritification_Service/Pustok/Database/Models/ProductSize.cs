using System.ComponentModel.DataAnnotations.Schema;

namespace Pustok.Database.Models;

[Table("ProductSize")]
public class ProductSize
{
    public Product Product { get; set; }
    public int ProductId { get; set; }


    public Size Size { get; set; }
    public int SizeId { get; set; }
}
