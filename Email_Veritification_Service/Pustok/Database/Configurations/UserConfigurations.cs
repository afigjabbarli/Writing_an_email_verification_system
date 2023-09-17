using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Pustok.Contracts;
using Pustok.Database.Models;
using System.Reflection.Emit;

namespace Pustok.Database.Configurations
{
    public class UserConfigurations : IEntityTypeConfiguration<User>
    {
        public void Configure(EntityTypeBuilder<User> builder)
        {
            builder
                .ToTable("Users");

            builder
                .HasData(
                new User
                {
                    Id = -1,
                    Name = "Eshqin",
                    LastName = "Heyder",
                    Email = "super_admin@gmail.com",
                    Password = BCrypt.Net.BCrypt.HashPassword("123321"),
                    Role = Role.Values.SuperAdmin,
                    UpdatedAt = new DateTime(2023, 09, 06, 0, 0, 0, DateTimeKind.Utc),
                    CreatedAt = new DateTime(2023, 09, 06, 0, 0, 0, DateTimeKind.Utc)
                });
        }
    }
}
