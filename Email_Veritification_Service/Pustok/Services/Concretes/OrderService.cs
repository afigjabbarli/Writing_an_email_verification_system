using Pustok.Database;
using Pustok.Services.Abstracts;

namespace Pustok.Services.Concretes;

public class OrderService : IOrderService
{
    private readonly PustokDbContext _pustokDbContext;
    private readonly Random _random;
    private const string TRACKINGCODE_PREFIX = "OR";

    public OrderService(PustokDbContext pustokDbContext)
    {
        _pustokDbContext = pustokDbContext;
        _random = new Random();
    }

    public string GenerateTrackingCode()
    {
        string trackingCode;

        do
        {
            int numberPart = _random.Next(100000, 1000000);
            trackingCode = TRACKINGCODE_PREFIX + numberPart;

        } while (_pustokDbContext.Orders.Any(o => o.TrackingCode == trackingCode));


        return trackingCode;
    }

}
