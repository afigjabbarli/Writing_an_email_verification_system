using Microsoft.AspNetCore.Mvc;
using Pustok.Database;
using Pustok.ViewModels;

namespace Pustok.Controllers;

public class HomeController : Controller //controller
{
    private readonly PustokDbContext _pustokDbContext;

    public HomeController(PustokDbContext pustokDbContext)
    {
        _pustokDbContext = pustokDbContext;
    }

    public IActionResult Index()
    {
        var model = new HomeViewModel
        {
            SlideBanners = _pustokDbContext.SlideBanners
               .OrderBy(sb => sb.Order)
               .ToList(),

            Products = _pustokDbContext.Products
               .OrderBy(p => p.Name)
               .ToList()
        };

        return View(model);
    }
}