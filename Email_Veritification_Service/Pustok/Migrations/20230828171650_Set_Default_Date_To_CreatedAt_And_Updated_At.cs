using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Pustok.Migrations
{
    public partial class Set_Default_Date_To_CreatedAt_And_Updated_At : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql(@"
                UPDATE ""Categories""
                SET 
                    ""CreatedAt"" = now(),
                    ""UpdatedAt"" = now()");


            migrationBuilder.Sql(@"
                UPDATE ""EmailMessages""
                SET 
                    ""CreatedAt"" = now(),
                    ""UpdatedAt"" = now()");


            migrationBuilder.Sql(@"
                UPDATE ""Products""
                SET 
                    ""CreatedAt"" = now(),
                    ""UpdatedAt"" = now()");

            migrationBuilder.Sql(@"
                UPDATE ""SlideBanners""
                SET 
                    ""CreatedAt"" = now(),
                    ""UpdatedAt"" = now()");
        }
    }
}
