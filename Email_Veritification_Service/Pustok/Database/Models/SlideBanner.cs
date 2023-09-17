using Pustok.Database.Base;

namespace Pustok.Database.Models;

public class SlideBanner : BaseEntity<int>, IAuditable
{
    public SlideBanner(string title, string description, string redirectionUrl, int order)
        : this(null, title, description, redirectionUrl, order) { }

    public SlideBanner(string offer, string title, string description, string redirectionUrl, int order)
    {
        Offer = offer;
        Title = title;
        Description = description;
        RedirectionUrl = redirectionUrl;
        Order = order;
    }

    public SlideBanner() { }

    public string Offer { get; set; }
    public string Title { get; set; }
    public string Description { get; set; }
    public string RedirectionUrl { get; set; }
    public int Order { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime UpdatedAt { get; set; }
}
