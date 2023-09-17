using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Pustok.Migrations
{
    public partial class User_Seeding : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.InsertData(
                table: "Users",
                columns: new[] { "Id", "CreatedAt", "Email", "LastName", "Name", "Password", "RoleId", "UpdatedAt" },
                values: new object[] { -1, new DateTime(2023, 9, 6, 0, 0, 0, 0, DateTimeKind.Utc), "super_admin@gmail.com", "Heyder", "Eshqin", "$2a$11$7Ils2Bedr/Yyo/.5yc0ORORBAAU24PmOi9NOJWVVMW06eK2JZ3WS2", -1, new DateTime(2023, 9, 6, 0, 0, 0, 0, DateTimeKind.Utc) });
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DeleteData(
                table: "Users",
                keyColumn: "Id",
                keyValue: -1);
        }
    }
}
