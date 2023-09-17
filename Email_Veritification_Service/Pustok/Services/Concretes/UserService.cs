using Microsoft.EntityFrameworkCore;
using Pustok.Contracts;
using Pustok.Database;
using Pustok.Database.Models;
using Pustok.Services.Abstracts;
using System.Linq;
using System.Security.Claims;

namespace Pustok.Services.Concretes;

public class UserService : IUserService
{
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly PustokDbContext _pustokDbContext;
    private User _currentUser;

    public UserService(IHttpContextAccessor httpContextAccessor, PustokDbContext pustokDbContext)
    {
        _httpContextAccessor = httpContextAccessor;
        _pustokDbContext = pustokDbContext;
    }

    public bool IsCurrentUserAuthenticated()
    {
        return _httpContextAccessor.HttpContext.User.Identity.IsAuthenticated;
    }

    public User CurrentUser
    {
        get
        {

            if (_currentUser != null)
            {
                return _currentUser;
            }

            if (_httpContextAccessor.HttpContext.User == null)
            {
                throw new Exception("User is not authenticated");
            }

            var userIdClaim = _httpContextAccessor.HttpContext.User.Claims.FirstOrDefault(c => c.Type == "id");
            if (userIdClaim is null)
            {
                throw new Exception("User is not authenticated");
            }

            var userId = Convert.ToInt32(userIdClaim.Value);
            var user = _pustokDbContext.Users.SingleOrDefault(u => u.Id == userId);
            if (user is null)
            {
                throw new Exception("User not found in system");
            }

            _currentUser = user;

            return _currentUser;
        }
    }

    public string GetCurrentUserFullName()
    {
        return $"{CurrentUser.Name} {CurrentUser.LastName}";
    }

    public string GetUserFullName(User user)
    {
        return $"{user.Name} {user.LastName}";
    }

    public bool DoesUserHaveRole(User user, Role.Values role)
    {
        return user.Role == role;
    }

    public List<Claim> GetClaimsAccordingToRole(User user)
    {
        var claims = new List<Claim>();
       
        switch (user.Role)
        {
            case Role.Values.User:
                claims.Add(new Claim(ClaimTypes.Role, Role.Names.User));
                break;
            case Role.Values.Admin:
                claims.Add(new Claim(ClaimTypes.Role, Role.Names.Admin));
                break;
            case Role.Values.Moderator:
                claims.Add(new Claim(ClaimTypes.Role, Role.Names.Moderator));
                break;
            case Role.Values.SuperAdmin:
                claims.Add(new Claim(ClaimTypes.Role, Role.Names.SuperAdmin));
                break;
            default:
                break;
        }

        return claims;
    }
}
