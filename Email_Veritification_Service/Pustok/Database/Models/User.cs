using Pustok.Contracts;
using Pustok.Database.Base;
using System.ComponentModel.DataAnnotations.Schema;

namespace Pustok.Database.Models;

public class User : BaseEntity<int>, IAuditable
{
    public string Name { get; set; }
    public string LastName { get; set; }
    public string Email { get; set; }
    public string Password { get; set; }


    public DateTime CreatedAt { get; set; }
    public DateTime UpdatedAt { get; set; }


    public Role.Values Role { get; set; } = Contracts.Role.Values.SuperAdmin;

    public List<Order> Orders { get; set; }
}
