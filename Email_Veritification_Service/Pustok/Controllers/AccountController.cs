using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Pustok.Contracts;
using Pustok.Database;
using Pustok.Services.Abstracts;
using Pustok.Services.Concretes;
using Pustok.ViewModels;

namespace Pustok.Controllers;

[Authorize]
[Route("account")]
public class AccountController : Controller
{
    private readonly PustokDbContext _dbContext;
    private readonly IUserService _userService;

    public AccountController(PustokDbContext dbContext, IUserService userService)
    {
        _dbContext = dbContext;
        _userService = userService;
    }

    [HttpGet("dashboard")]
    public IActionResult Dashboard()
    {
        var user1 = _userService.CurrentUser;



        return View();
    }

    [HttpGet("orders")]
    public IActionResult Orders()
    {
        var orders = _dbContext.Orders
            .Where(o => o.UserId == _userService.CurrentUser.Id)
            .Select(o => new OrderViewModel
            {
                OrderId = o.Id,
                TrackingCode = o.TrackingCode,
                CreatedAt = o.CreatedAt,
                StatusName = o.Status.ToString(),
                Total = o.OrderItems.Sum(oi => oi.ProductQuantity * oi.ProductPrice),
                Quantity = o.OrderItems.Count
            })
            .ToList();

        return View(orders);
    }

    [HttpGet("orders/{id}/items")]
    public IActionResult OrderDetails(int id)
    {
        var orderItems = _dbContext.OrderItems
            .Where(oi =>
                oi.Order.UserId == _userService.CurrentUser.Id &&
                oi.OrderId == id)
            .Select(oi => new OrderItemViewModel
            {
                ProductName = oi.ProductName,
                ProductDescription = oi.ProductDescription,
                ProductOrderPhoto = oi.ProductOrderPhoto,
                ProductPrice = oi.ProductPrice,
                ProductQuantity = oi.ProductQuantity,
                ProductSizeName = oi.ProductSizeName,
                ProductColorName = oi.ProductColorName,
            })
            .ToList();

        return Json(orderItems);
    }

    [HttpGet("addresses")]
    public IActionResult Addresses()
    {
        return View();
    }


    [HttpGet("account-details")]
    public IActionResult AccountDetails()
    {
        return View();
    }

    [HttpGet("logout")]
    public IActionResult Logout()
    {
        //logic

        return RedirectToAction("index", "home");
    }

}
