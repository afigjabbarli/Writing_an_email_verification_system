using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Pustok.Contracts;
using Pustok.Database;
using Pustok.Services.Abstracts;
using Pustok.ViewModels;

namespace Pustok.Controllers;

[Route("products")]
public class ProductController : Controller
{
    private readonly PustokDbContext _dbContext;
    private readonly IFileService _fileService;


    public ProductController(PustokDbContext dbContext, IFileService fileService)
    {
        _dbContext = dbContext;
        _fileService = fileService;
    }

    [HttpGet("{id}/details")]
    public IActionResult GetDetails(int id)
    {
        var product = _dbContext.Products.SingleOrDefault(p => p.Id == id);
        if (product == null)
        {
            return NotFound();
        }

        var model = new ProductDetailsViewModel
        {
            ProductId = product.Id,
            Name = product.Name,
            Description = product.Description,
            Price = product.Price,
            Sizes = _dbContext.ProductSizes
                .Where(ps => ps.ProductId == product.Id)
                .Select(ps => new ProductDetailsViewModel.SizeViewModel
                    {
                      Id = ps.Size.Id,
                      Name = ps.Size.Name
                    })
                .ToList(),
            Categories = _dbContext.CategoryProducts
                .Where(cp => cp.ProductId == product.Id)
                .Select(cp => cp.Category.Name)
                .ToList(),
            Colors = _dbContext.ProductColors
                .Where(cp => cp.ProductId == product.Id)
                .Select(ps => new ProductDetailsViewModel.ColorViewModel
                    {
                        Id = ps.Color.Id,
                        Name = ps.Color.Name
                    })
                .ToList(),
            ImageUrl = _fileService
                .GetStaticFilesUrl(CustomUploadDirectories.Products, product.PhysicalImageName)
        };

        return Json(model);
    }
}
