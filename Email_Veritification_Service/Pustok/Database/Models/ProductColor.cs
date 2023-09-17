using System.ComponentModel.DataAnnotations.Schema;

namespace Pustok.Database.Models;

[Table("ProductColor")]
public class ProductColor
{
    public Product Product { get; set; }
    public int ProductId { get; set; }


    public Color Color { get; set; }
    public int ColorId { get; set; }
}
