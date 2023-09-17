using System.ComponentModel.DataAnnotations;

namespace Pustok.ViewModels;

public class RegisterViewModel
{
    [Required]
    public string Name { get; set; }

    [Required]
    public string LastName { get; set; }

    [Required]
    public string Email { get; set; }

    [Required]
    public string Password { get; set; }

    [Required]
    [Compare("Password", ErrorMessage = "Password's doesn't match")]
    public string ConfirmPassword { get; set; }
}
