using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Pustok.Contracts;

namespace Pustok.Areas.Admin.Controllers;

[Area("admin")]
[Authorize(Roles = Role.Names.SuperAdmin)]
public class DashboardController : Controller
{
    public IActionResult Index()
    {
        return View();
    }
}
