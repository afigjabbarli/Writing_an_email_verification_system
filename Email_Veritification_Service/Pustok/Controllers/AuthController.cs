using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Pustok.Contracts;
using Pustok.Database;
using Pustok.Database.Models;
using Pustok.Services.Abstracts;
using Pustok.Services.Concretes;
using Pustok.ViewModels;
using System.Security.Claims;

namespace Pustok.Controllers;

public class AuthController : Controller
{
    private readonly PustokDbContext _dbContext;
    private readonly IUserService _userService;
    private readonly IVerificationService _verificationService;

    public AuthController(PustokDbContext dbContext, IUserService userService, IVerificationService verificationService)
    {
        _dbContext = dbContext;
        _userService = userService;
        _verificationService = verificationService;
    }

    #region Login

    [HttpGet]
    public async Task<IActionResult> Login()
    {
        if (_userService.IsCurrentUserAuthenticated())
        {
            return RedirectToAction("index", "home");
        }


        return View();
    }

    [HttpPost]
    public async Task<IActionResult> Login(LoginViewModel model)
    {
        if (!ModelState.IsValid)
            return View(model);

        var user = _dbContext.Users.SingleOrDefault(u => u.Email == model.Email);
        if (user is null)
        {
            ModelState.AddModelError("Password", "Email not found");
            return View(model);
        }

        if (!BCrypt.Net.BCrypt.Verify(model.Password, user.Password))
        {
            ModelState.AddModelError("Password", "Password is not valid");
            return View(model);
        }

        var claims = new List<Claim>
        {
            new Claim("id", user.Id.ToString()),
        };

        claims.AddRange(_userService.GetClaimsAccordingToRole(user));

         var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
        var claimsPricipal = new ClaimsPrincipal(claimsIdentity);

        await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, claimsPricipal);

        return RedirectToAction("index", "home");
    }

    #endregion

    #region Register

    [HttpGet]
    public IActionResult Register()
    {
        if (_userService.IsCurrentUserAuthenticated())
        {
            return RedirectToAction("index", "home");
        }

        return View();
    }

    [HttpPost]
    public IActionResult Register(RegisterViewModel model)
    {
        if (!ModelState.IsValid)
        {
            return View(model);
        }

        if (_dbContext.Users.Any(u => u.Email == model.Email))
        {
            ModelState.AddModelError("Email", "This email already used");
            return View(model);
        }

        var user = new User
        {
            Name = model.Name,
            LastName = model.LastName,
            Email = model.Email,
            Password = BCrypt.Net.BCrypt.HashPassword(model.Password),
        };

        string token = _verificationService.GenerateRandomVerificationToken();
        user.VerificationToken = token; 

        _dbContext.Add(user);
        _dbContext.SaveChanges();

        try
        {
            User activatedUser = _dbContext.Users.Single(u => model.Email == u.Email);
            _verificationService.SendAccountActivationURL(activatedUser, activatedUser.Id, token);
        }
        catch (InvalidOperationException ex)
        {

            throw ex;
        }
        

        return RedirectToAction("Index", "Home");
    }
    public IActionResult Verify([FromQuery] int ID, [FromQuery] string token)
    {
        DateTime currentTime = DateTime.UtcNow;    
        var user = _dbContext.Users.SingleOrDefault(u => u.VerificationToken == token && u.Id == ID);
        if (user != null)
        {
            if(currentTime.Hour - user.CreatedAt.Hour <= 2)
            {
                user.IsEmailVerified = true;
                _dbContext.Update(user);
                _dbContext.SaveChanges();
                RedirectToAction("Login", "Auth");
            }
            else
            {
                ViewBag.ErrorMessage = "Activation link has expired!";
                RedirectToAction("Register", "Auth");
            }
        }
        return NotFound("User not found");
    }
    #endregion

    #region Logout

    [HttpGet]
    public async Task<IActionResult> Logout()
    {
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

        return RedirectToAction("index", "home");
    }


    #endregion
}
