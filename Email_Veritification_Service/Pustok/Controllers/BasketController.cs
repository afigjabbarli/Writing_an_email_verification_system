using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Pustok.Contracts;
using Pustok.Database;
using Pustok.Database.Models;
using Pustok.Services.Abstracts;
using Pustok.Services.Concretes;
using Pustok.ViewModels;
using System.Text.Json;

namespace Pustok.Controllers;

[Route("basket")]
public class BasketController : Controller
{
    private readonly PustokDbContext _dbContext;
    private readonly IUserService _userService;
    private readonly IBasketService _basketService;

    public BasketController(PustokDbContext dbContext, IUserService userService, IBasketService basketService)
    {
        _dbContext = dbContext;
        _userService = userService;
        _basketService = basketService;
    }

    [HttpPost("add-product/{productId}")]
    public IActionResult AddProduct(AddProductToBasketViewModel model)
    {
        var product = _dbContext.Products.SingleOrDefault(p => p.Id == model.ProductId);
        if (product == null)
        {
            return NotFound();
        }

        var productColor = _dbContext.ProductColors
            .FirstOrDefault(pc =>
                pc.ProductId == product.Id
                && (model.ColorId != null ? pc.ColorId == model.ColorId : true));
        if (productColor == null)
        {
            return NotFound();
        }

        var productSize = _dbContext.ProductSizes
            .FirstOrDefault(ps =>
                ps.ProductId == product.Id &&
                model.SizeId != null ? ps.SizeId == model.SizeId : true);
        if (productSize == null)
        {
            return NotFound();
        }

        _basketService
            .AddToBasket(product.Id, productColor.ColorId, productSize.SizeId, model.Quantity);

        _dbContext.SaveChanges();

        return Ok();
    }

    public IActionResult Index()
    {
        return View();
    }
}
