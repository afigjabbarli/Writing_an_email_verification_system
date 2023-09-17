using Pustok.Database.Base;

namespace Pustok.Database.Models;

public class EmailMessage : BaseEntity<int>, IAuditable
{
    public string Subject { get; set; }
    public string Content { get; set; }
    public List<string> Receipents { get; set; }

    public DateTime CreatedAt { get; set; }
    public DateTime UpdatedAt { get; set; }
}
