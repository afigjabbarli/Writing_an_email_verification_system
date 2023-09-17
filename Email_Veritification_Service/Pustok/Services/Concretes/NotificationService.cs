using Pustok.Contracts;
using Pustok.Database.Models;
using Pustok.Exceptions;
using Pustok.Services.Abstracts;
using System.Text;

namespace Pustok.Services.Concretes;

public class NotificationService : INotificationService
{
    private readonly IEmailService _emailService;

    public NotificationService(IEmailService emailService)
    {
        _emailService = emailService;
    }

    public void SendOrderNotification(Order order)
    {
        switch (order.Status)
        {
            case OrderStatus.Approved:
                SendOrderApprovedNotification(order);
                break;
            case OrderStatus.Rejected:
                SendOrderRejectedNotification(order);
                break;
            case OrderStatus.Sent:
                SendOrderSentNotification(order);
                break;
            case OrderStatus.Completed:
                SendOrderCompletedNotification(order);
                break;
            default:
                throw new NotificationNotImplementedException();
        }
    }

    
    public void SendOrderApprovedNotification(Order order)
    {
        var message = PrepareOrderApprovedMessage(order);
        _emailService.SendEmail(EmailTemplates.Order.SUBJECT, message, order.User.Email);
    }
    private string PrepareOrderApprovedMessage(Order order)
    {
        var templayeBuilder = new StringBuilder(EmailTemplates.Order.APPROVED)
            .Replace("{firstName}", order.User.Name)
            .Replace("{lastName}", order.User.LastName)
            .Replace("{order_number}", order.TrackingCode);

        return templayeBuilder.ToString();
    }


    public void SendOrderCompletedNotification(Order order)
    {
        var message = PrepareOrderCompletedMessage(order);
        _emailService.SendEmail(EmailTemplates.Order.SUBJECT, message, order.User.Email);
    }
    private string PrepareOrderCompletedMessage(Order order)
    {
        var templayeBuilder = new StringBuilder(EmailTemplates.Order.COMPLETED)
            .Replace("{firstName}", order.User.Name)
            .Replace("{lastName}", order.User.LastName)
            .Replace("{order_number}", order.TrackingCode);

        return templayeBuilder.ToString();
    }


    public void SendOrderRejectedNotification(Order order)
    {
        var message = PrepareOrderRejectedMessage(order);
        _emailService.SendEmail(EmailTemplates.Order.SUBJECT, message, order.User.Email);
    }
    private string PrepareOrderRejectedMessage(Order order)
    {
        var templayeBuilder = new StringBuilder(EmailTemplates.Order.REJECTED)
            .Replace("{firstName}", order.User.Name)
            .Replace("{lastName}", order.User.LastName)
            .Replace("{order_number}", order.TrackingCode);

        return templayeBuilder.ToString();
    }


    public void SendOrderSentNotification(Order order)
    {
        var message = PrepareOrderRejectedMessage(order);
        _emailService.SendEmail(EmailTemplates.Order.SUBJECT, message, order.User.Email);
    }
    private string PrepareOrderSentMessage(Order order)
    {
        var templayeBuilder = new StringBuilder(EmailTemplates.Order.SENT)
            .Replace("{firstName}", order.User.Name)
            .Replace("{lastName}", order.User.LastName)
            .Replace("{order_number}", order.TrackingCode);

        return templayeBuilder.ToString();
    }
}
