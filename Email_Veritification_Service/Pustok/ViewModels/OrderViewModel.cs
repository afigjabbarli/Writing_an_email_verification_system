namespace Pustok.ViewModels;

public class OrderViewModel
{
    public int OrderId { get; set; }

    public string TrackingCode { get; set; }
    public DateTime CreatedAt { get; set; }
    public string StatusName { get; set; }
    public decimal Total { get; set; }
    public int Quantity { get; set; }
}
