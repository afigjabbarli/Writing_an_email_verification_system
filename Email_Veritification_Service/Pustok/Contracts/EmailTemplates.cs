namespace Pustok.Contracts;

public static class EmailTemplates
{
    public class Order
    {
        public const string SUBJECT = "Sifarisle bagli yenilik";
      
        public const string APPROVED = "Hörmətli {firstName} {lastName}, sizin {order_number} təsdiqləndi";
        public const string REJECTED = "Hörmətli {firstName} {lastName}, sizin {order_number}  təsdiqlənmədi.";
        public const string SENT = "Hörmətli {firstName} {lastName}, sizin {order_number} göndərildi, kuryer sizinlə əlaqə saxlayacaq.";
        public const string COMPLETED = "Hörmətli {firstName} {lastName}, sizin {order_number} kuryer tərəfindən təhvil verildi.";
    }

}
