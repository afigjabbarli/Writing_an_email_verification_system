using Pustok.Contracts;

namespace Pustok.Areas.Admin.ViewModels.Order
{
    public class OrderUpdateViewModel
    {
        public int Id { get; set; } // The ID of the order being updated
        public OrderStatus Status { get; set; } // Status of the order
        public string TrackingCode { get; set; } // Tracking code for the order
        public string UserFullName { get; set; } // Full name of the user who placed the order
        public DateTime CreatedAt { get; set; } // Date and time when the order was created
    }
}
