using Pustok.Database.Models;

namespace Pustok.Services.Abstracts
{
    public interface INotificationService
    {
        void SendOrderNotification(Order order);
        public void SendOrderApprovedNotification(Order order);
        public void SendOrderRejectedNotification(Order order);
        public void SendOrderSentNotification(Order order);
        public void SendOrderCompletedNotification(Order order);

    }
}
