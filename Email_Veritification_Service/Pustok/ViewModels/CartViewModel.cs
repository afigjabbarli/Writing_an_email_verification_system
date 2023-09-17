namespace Pustok.ViewModels;

public class CartViewModel
{
    public List<BasketItemViewModel> BasketItems { get; set; } = new List<BasketItemViewModel>();
    public decimal Total { get; set; }

    public class BasketItemViewModel
    {
        public int ProductId { get; set; }
        public string ProductName { get; set; }
        public string SizeName { get; set; }
        public string ColorName { get; set; }
        public decimal ProductPrice { get; set; }
        public int ProductQuantity { get; set; }
        public string ImageUrl { get; set; }
    }
}


