using Pustok.Database.Models;

namespace Pustok.Areas.Admin.ViewModels.Order
{
    public class OrderDetailsViewModel
    {
        public string TrackingCode { get; set; }
        public string OwnerFullName { get; set; }
        public List<OrderItem> Items { get; set; }
    }
}
