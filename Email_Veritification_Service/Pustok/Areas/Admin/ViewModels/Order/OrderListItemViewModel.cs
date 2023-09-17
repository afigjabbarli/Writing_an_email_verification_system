using Pustok.Contracts;

namespace Pustok.Areas.Admin.ViewModels.Order
{
    public class OrderListItemViewModel
    {
        public int Id { get; set; } // You can include this if you need to display the order ID in the list
        public OrderStatus Status { get; set; }
        public string StatusName { get; set; } // Status of the order
        public string TrackingCode { get; set; } // Tracking code for the order
        public string UserFullName { get; set; } // Full name of the user who placed the order
        public DateTime CreatedAt { get; set; } // Date and time when the order was created
    }
}
