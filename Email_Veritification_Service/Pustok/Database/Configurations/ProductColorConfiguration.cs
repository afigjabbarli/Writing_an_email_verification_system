using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Pustok.Database.Models;
using System.Reflection.Emit;

namespace Pustok.Database.Configurations
{
    public class ProductColorConfiguration : IEntityTypeConfiguration<ProductColor>
    {
        public void Configure(EntityTypeBuilder<ProductColor> builder)
        {
            builder
                .HasKey(pc => new { pc.ProductId, pc.ColorId });

            builder
               .HasOne<Product>(pc => pc.Product)
               .WithMany(p => p.ProductColors)
               .HasForeignKey(pc => pc.ProductId);

            builder
                .HasOne<Color>(pc => pc.Color)
               .WithMany(p => p.ProductColors)
               .HasForeignKey(pc => pc.ColorId);

        }
    }
}
