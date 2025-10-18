using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SmtpGmailDemo.Migrations
{
    /// <inheritdoc />
    public partial class AddFieldsToCustomUserTokens : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<DateTime>(
                name: "ExpiresAt",
                table: "CustomUserTokens",
                type: "datetime2",
                nullable: true);

            migrationBuilder.AddColumn<bool>(
                name: "IsUsed",
                table: "CustomUserTokens",
                type: "bit",
                nullable: false,
                defaultValue: false);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "ExpiresAt",
                table: "CustomUserTokens");

            migrationBuilder.DropColumn(
                name: "IsUsed",
                table: "CustomUserTokens");
        }
    }
}
