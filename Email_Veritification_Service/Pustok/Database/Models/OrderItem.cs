using Pustok.Database.Base;

namespace Pustok.Database.Models;

public class OrderItem : BaseEntity<int>, IAuditable
{
    public int OrderId { get; set; }
    public Order Order { get; set; }

    public string ProductName { get; set; }
    public decimal ProductPrice { get; set; }
    public string ProductOrderPhoto { get; set; }
    public int ProductQuantity { get; set; }
    public string ProductDescription { get; set; }
    public string ProductSizeName { get; set; }
    public string ProductColorName { get; set; }

    public DateTime CreatedAt { get; set; }
    public DateTime UpdatedAt { get; set; }
}
