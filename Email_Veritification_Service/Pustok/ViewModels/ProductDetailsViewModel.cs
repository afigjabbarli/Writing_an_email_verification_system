namespace Pustok.ViewModels
{
    public class ProductDetailsViewModel
    {
        public int ProductId { get; set; }
        public string Name { get; set; }
        public string Description { get; set; }
        public decimal Price { get; set; }
        public List<ColorViewModel> Colors { get; set; }
        public List<SizeViewModel> Sizes { get; set; }
        public List<string> Categories { get; set; }
        public string ImageUrl { get; set; }


        public class ColorViewModel
        {
            public int Id { get; set; }
            public string Name { get; set; }
        }
        public class SizeViewModel
        {
            public int Id { get; set; }
            public string Name { get; set; }
        }
    }
}
