using Microsoft.EntityFrameworkCore;
using Pustok.Contracts;
using Pustok.Database.Base;
using Pustok.Database.Configurations;
using Pustok.Database.Models;

namespace Pustok.Database;

public class PustokDbContext : DbContext
{
    public PustokDbContext(DbContextOptions<PustokDbContext> options)
        : base(options) { }

    public override int SaveChanges()
    {
        foreach (var entry in ChangeTracker.Entries())
        {
            if (entry.Entity is not IAuditable)
                continue;

            IAuditable auditable = (IAuditable)entry.Entity;

            if (entry.State == EntityState.Added)
            {
                auditable.CreatedAt = DateTime.UtcNow;
                auditable.UpdatedAt = DateTime.UtcNow;
            }
            else if (entry.State == EntityState.Modified)
            {
                auditable.UpdatedAt = DateTime.UtcNow;
            }
        }


        return base.SaveChanges();
    }


    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.ApplyConfigurationsFromAssembly(typeof(PustokDbContext).Assembly);

        #region Product size

        modelBuilder
            .Entity<ProductSize>()
            .HasKey(ps => new { ps.ProductId, ps.SizeId });

        modelBuilder
           .Entity<ProductSize>()
           .HasOne<Product>(ps => ps.Product)
           .WithMany(ps => ps.ProductSizes)
           .HasForeignKey(ps => ps.ProductId);

        modelBuilder
          .Entity<ProductSize>()
          .HasOne<Size>(ps => ps.Size)
          .WithMany(s => s.ProductSizes)
          .HasForeignKey(ps => ps.SizeId);

        #endregion

        #region Sizes

        modelBuilder
            .Entity<Size>()
            .ToTable("Size");

        modelBuilder
            .Entity<Size>()
            .HasData(
                new Size
                {
                    Id = -1,
                    Name = "X",
                    UpdatedAt = new DateTime(2023, 08, 30, 0, 0, 0, DateTimeKind.Utc),
                    CreatedAt = new DateTime(2023, 08, 30, 0, 0, 0, DateTimeKind.Utc),
                },
                new Size
                {
                    Id = -2,
                    Name = "S",
                    UpdatedAt = new DateTime(2023, 08, 30, 0, 0, 0, DateTimeKind.Utc),
                    CreatedAt = new DateTime(2023, 08, 30, 0, 0, 0, DateTimeKind.Utc),
                },
                new Size
                {
                    Id = -3,
                    Name = "XS",
                    UpdatedAt = new DateTime(2023, 08, 30, 0, 0, 0, DateTimeKind.Utc),
                    CreatedAt = new DateTime(2023, 08, 30, 0, 0, 0, DateTimeKind.Utc),
                },
                new Size
                {
                    Id = -4,
                    Name = "L",
                    UpdatedAt = new DateTime(2023, 08, 30, 0, 0, 0, DateTimeKind.Utc),
                    CreatedAt = new DateTime(2023, 08, 30, 0, 0, 0, DateTimeKind.Utc),
                },
                new Size
                {
                    Id = -5,
                    Name = "XL",
                    UpdatedAt = new DateTime(2023, 08, 30, 0, 0, 0, DateTimeKind.Utc),
                    CreatedAt = new DateTime(2023, 08, 30, 0, 0, 0, DateTimeKind.Utc),
                },
                new Size
                {
                    Id = -6,
                    Name = "XXL",
                    UpdatedAt = new DateTime(2023, 08, 30, 0, 0, 0, DateTimeKind.Utc),
                    CreatedAt = new DateTime(2023, 08, 30, 0, 0, 0, DateTimeKind.Utc),
                }
            );

        #endregion

        #region Colors

        modelBuilder
           .Entity<Color>()
           .ToTable("Color");

        modelBuilder
            .Entity<Color>()
            .HasData(
                new Color
                {
                    Id = -1,
                    Name = "Blue",
                    UpdatedAt = new DateTime(2023, 08, 30, 0, 0, 0, DateTimeKind.Utc),
                    CreatedAt = new DateTime(2023, 08, 30, 0, 0, 0, DateTimeKind.Utc),
                },
                new Size
                {
                    Id = -2,
                    Name = "Red",
                    UpdatedAt = new DateTime(2023, 08, 30, 0, 0, 0, DateTimeKind.Utc),
                    CreatedAt = new DateTime(2023, 08, 30, 0, 0, 0, DateTimeKind.Utc),
                },
                new Size
                {
                    Id = -3,
                    Name = "Green",
                    UpdatedAt = new DateTime(2023, 08, 30, 0, 0, 0, DateTimeKind.Utc),
                    CreatedAt = new DateTime(2023, 08, 30, 0, 0, 0, DateTimeKind.Utc),
                },
                new Size
                {
                    Id = -4,
                    Name = "Purple",
                    UpdatedAt = new DateTime(2023, 08, 30, 0, 0, 0, DateTimeKind.Utc),
                    CreatedAt = new DateTime(2023, 08, 30, 0, 0, 0, DateTimeKind.Utc),
                },
                new Size
                {
                    Id = -5,
                    Name = "Yellow",
                    UpdatedAt = new DateTime(2023, 08, 30, 0, 0, 0, DateTimeKind.Utc),
                    CreatedAt = new DateTime(2023, 08, 30, 0, 0, 0, DateTimeKind.Utc),
                },
                new Size
                {
                    Id = -6,
                    Name = "Black",
                    UpdatedAt = new DateTime(2023, 08, 30, 0, 0, 0, DateTimeKind.Utc),
                    CreatedAt = new DateTime(2023, 08, 30, 0, 0, 0, DateTimeKind.Utc),
                }
            );

        #endregion

        #region Categories

        modelBuilder
            .Entity<Category>()
            .HasData(
                new Category
                {
                    Id = -1,
                    Name = "Laundry",
                    UpdatedAt = new DateTime(2023, 08, 30, 0, 0, 0, DateTimeKind.Utc),
                    CreatedAt = new DateTime(2023, 08, 30, 0, 0, 0, DateTimeKind.Utc),
                },
                new Category
                {
                    Id = -2,
                    Name = "Fruts",
                    UpdatedAt = new DateTime(2023, 08, 30, 0, 0, 0, DateTimeKind.Utc),
                    CreatedAt = new DateTime(2023, 08, 30, 0, 0, 0, DateTimeKind.Utc),
                },
                new Category
                {
                    Id = -3,
                    Name = "Sport",
                    UpdatedAt = new DateTime(2023, 08, 30, 0, 0, 0, DateTimeKind.Utc),
                    CreatedAt = new DateTime(2023, 08, 30, 0, 0, 0, DateTimeKind.Utc),
                },
                new Category
                {
                    Id = -4,
                    Name = "Classic sport",
                    UpdatedAt = new DateTime(2023, 08, 30, 0, 0, 0, DateTimeKind.Utc),
                    CreatedAt = new DateTime(2023, 08, 30, 0, 0, 0, DateTimeKind.Utc),
                });


        #endregion


        base.OnModelCreating(modelBuilder);
    }


    public DbSet<Product> Products { get; set; }
    public DbSet<CategoryProduct> CategoryProducts { get; set; }
    public DbSet<SlideBanner> SlideBanners { get; set; }
    public DbSet<Category> Categories { get; set; }
    public DbSet<Size> Sizes { get; set; }
    public DbSet<Color> Colors { get; set; }
    public DbSet<EmailMessage> EmailMessages { get; set; }
    public DbSet<ProductColor> ProductColors { get; set; }
    public DbSet<ProductSize> ProductSizes { get; set; }
    public DbSet<User> Users { get; set; }
    public DbSet<Order> Orders { get; set; }
    public DbSet<OrderItem> OrderItems { get; set; }
}
