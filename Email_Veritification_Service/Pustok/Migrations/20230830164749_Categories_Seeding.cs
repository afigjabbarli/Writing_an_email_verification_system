using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Pustok.Migrations
{
    public partial class Categories_Seeding : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.InsertData(
                table: "Categories",
                columns: new[] { "Id", "CreatedAt", "Name", "UpdatedAt" },
                values: new object[,]
                {
                    { -4, new DateTime(2023, 8, 30, 0, 0, 0, 0, DateTimeKind.Utc), "Classic sport", new DateTime(2023, 8, 30, 0, 0, 0, 0, DateTimeKind.Utc) },
                    { -3, new DateTime(2023, 8, 30, 0, 0, 0, 0, DateTimeKind.Utc), "Sport", new DateTime(2023, 8, 30, 0, 0, 0, 0, DateTimeKind.Utc) },
                    { -2, new DateTime(2023, 8, 30, 0, 0, 0, 0, DateTimeKind.Utc), "Fruts", new DateTime(2023, 8, 30, 0, 0, 0, 0, DateTimeKind.Utc) },
                    { -1, new DateTime(2023, 8, 30, 0, 0, 0, 0, DateTimeKind.Utc), "Laundry", new DateTime(2023, 8, 30, 0, 0, 0, 0, DateTimeKind.Utc) }
                });
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DeleteData(
                table: "Categories",
                keyColumn: "Id",
                keyValue: -4);

            migrationBuilder.DeleteData(
                table: "Categories",
                keyColumn: "Id",
                keyValue: -3);

            migrationBuilder.DeleteData(
                table: "Categories",
                keyColumn: "Id",
                keyValue: -2);

            migrationBuilder.DeleteData(
                table: "Categories",
                keyColumn: "Id",
                keyValue: -1);
        }
    }
}
