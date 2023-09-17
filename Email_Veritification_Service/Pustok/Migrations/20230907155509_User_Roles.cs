using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Pustok.Migrations
{
    public partial class User_Roles : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<int>(
                name: "Role",
                table: "Users",
                type: "integer",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.UpdateData(
                table: "Users",
                keyColumn: "Id",
                keyValue: -1,
                columns: new[] { "Password", "Role" },
                values: new object[] { "$2a$11$nsqeTYFg2NjNjVIhzjo9gu2YaStErb05wHcCLrgopSmdW7yMafMOS", 4 });
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "Role",
                table: "Users");

            migrationBuilder.UpdateData(
                table: "Users",
                keyColumn: "Id",
                keyValue: -1,
                column: "Password",
                value: "$2a$11$JAc7vPOOTFv6lMx4kcTyLOLrv6YZgeQt3rzfcfrw4CmkZcRi0P1.i");
        }
    }
}
