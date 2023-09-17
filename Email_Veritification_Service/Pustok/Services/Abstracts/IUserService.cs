using Pustok.Contracts;
using Pustok.Database.Models;
using System.Security.Claims;

namespace Pustok.Services.Abstracts;

public interface IUserService
{
    public User CurrentUser { get; }

    string GetCurrentUserFullName();
    bool IsCurrentUserAuthenticated();
    List<Claim> GetClaimsAccordingToRole(User user);

    string GetUserFullName(User user);
}
