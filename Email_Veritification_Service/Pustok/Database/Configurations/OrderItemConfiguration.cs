using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Pustok.Database.Models;
using System.Reflection.Emit;

namespace Pustok.Database.Configurations;

public class OrderItemConfiguration : IEntityTypeConfiguration<OrderItem>
{
    public void Configure(EntityTypeBuilder<OrderItem> builder)
    {
        //FLUENT API
        builder
             .ToTable("OrdersItems");
    }
}
