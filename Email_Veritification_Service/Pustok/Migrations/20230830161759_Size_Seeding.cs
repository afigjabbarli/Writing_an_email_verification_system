using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Pustok.Migrations
{
    public partial class Size_Seeding : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.InsertData(
                table: "Size",
                columns: new[] { "Id", "CreatedAt", "Name", "UpdatedAt" },
                values: new object[,]
                {
                    { -6, new DateTime(2023, 8, 30, 0, 0, 0, 0, DateTimeKind.Utc), "XXL", new DateTime(2023, 8, 30, 0, 0, 0, 0, DateTimeKind.Utc) },
                    { -5, new DateTime(2023, 8, 30, 0, 0, 0, 0, DateTimeKind.Utc), "XL", new DateTime(2023, 8, 30, 0, 0, 0, 0, DateTimeKind.Utc) },
                    { -4, new DateTime(2023, 8, 30, 0, 0, 0, 0, DateTimeKind.Utc), "L", new DateTime(2023, 8, 30, 0, 0, 0, 0, DateTimeKind.Utc) },
                    { -3, new DateTime(2023, 8, 30, 0, 0, 0, 0, DateTimeKind.Utc), "XS", new DateTime(2023, 8, 30, 0, 0, 0, 0, DateTimeKind.Utc) },
                    { -2, new DateTime(2023, 8, 30, 0, 0, 0, 0, DateTimeKind.Utc), "S", new DateTime(2023, 8, 30, 0, 0, 0, 0, DateTimeKind.Utc) },
                    { -1, new DateTime(2023, 8, 30, 0, 0, 0, 0, DateTimeKind.Utc), "X", new DateTime(2023, 8, 30, 0, 0, 0, 0, DateTimeKind.Utc) }
                });
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DeleteData(
                table: "Size",
                keyColumn: "Id",
                keyValue: -6);

            migrationBuilder.DeleteData(
                table: "Size",
                keyColumn: "Id",
                keyValue: -5);

            migrationBuilder.DeleteData(
                table: "Size",
                keyColumn: "Id",
                keyValue: -4);

            migrationBuilder.DeleteData(
                table: "Size",
                keyColumn: "Id",
                keyValue: -3);

            migrationBuilder.DeleteData(
                table: "Size",
                keyColumn: "Id",
                keyValue: -2);

            migrationBuilder.DeleteData(
                table: "Size",
                keyColumn: "Id",
                keyValue: -1);
        }
    }
}
