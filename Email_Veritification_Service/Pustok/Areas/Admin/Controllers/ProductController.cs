using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Pustok.Areas.Admin.ViewModels.Product;
using Pustok.Contracts;
using Pustok.Database;
using Pustok.Database.Models;
using Pustok.Services.Abstracts;

namespace Pustok.Areas.Admin.Controllers;

[Route("admin/products")]
[Area("admin")]
[Authorize(Roles = Role.Names.SuperAdmin)]
public class ProductController : Controller
{
    private readonly PustokDbContext _dbContext;
    private readonly IFileService _fileService;

    public ProductController(PustokDbContext dbContext, IFileService fileService)
    {
        _dbContext = dbContext;
        _fileService = fileService;
    }

    #region Index

    [HttpGet]
    public IActionResult Index()
    {
        var products = _dbContext.Products
            .OrderBy(p => p.Name)
            .ToList();

        var productViewModels = products
            .Select(p => new ProductListItemViewModel
            {
                Id = p.Id,
                Name = p.Name,
                Description = p.Description,
                Color = default,
                Size = default,
                Price = p.Price,
            })
            .ToList();

        return View(productViewModels);
    }

    #endregion

    #region Add

    [HttpGet("add")]
    public IActionResult Add()
    {
        var model = new ProductAddViewModel
        {
            Categories = _dbContext.Categories.ToList(),
            Sizes = _dbContext.Sizes.ToList(),
            Colors = _dbContext.Colors.ToList(),
        };

        return View(model);
    }

    [HttpPost("add")]
    public IActionResult Add(ProductAddViewModel model)
    {
        if (!ModelState.IsValid)
        {
            model.Categories = _dbContext.Categories.ToList();
            model.Sizes = _dbContext.Sizes.ToList();
            model.Colors = _dbContext.Colors.ToList();
            return View(model);
        }

        var product = new Product
        {
            Name = model.Name,
            Description = model.Description,
            Price = model.Price,
        };

        if (model.Image is not null)
        {
            product.PhysicalImageName = _fileService
                .Upload(model.Image, CustomUploadDirectories.Products); ;
        }

        _dbContext.Products.Add(product);

        #region Category addition

        foreach (var categoryId in model.CategoryIds)
        {
            var category = _dbContext.Categories.SingleOrDefault(c => c.Id == categoryId);
            if (category == null)
            {
                model.Categories = _dbContext.Categories.ToList();
                ModelState.AddModelError("CategoryIds", "Category not found");
                return View(model);
            }

            var productCategory = new CategoryProduct
            {
                CategoryId = category.Id,
                Product = product,
            };

            _dbContext.CategoryProducts.Add(productCategory);
        }

        #endregion

        #region Size addition

        foreach (var sizeId in model.SizeIds)
        {
            var size = _dbContext.Sizes.SingleOrDefault(c => c.Id == sizeId);
            if (size == null)
            {
                model.Categories = _dbContext.Categories.ToList();
                model.Sizes = _dbContext.Sizes.ToList();
                model.Colors = _dbContext.Colors.ToList();
                ModelState.AddModelError("SizeIds", "Size not found");
                return View(model);
            }

            var productSize = new ProductSize
            {
                SizeId = size.Id,
                Product = product,
            };

            _dbContext.ProductSizes.Add(productSize);
        }

        #endregion

        #region Color addition

        foreach (var colorId in model.ColorIds)
        {
            var color = _dbContext.Colors.SingleOrDefault(c => c.Id == colorId);
            if (color == null)
            {
                model.Categories = _dbContext.Categories.ToList();
                model.Sizes = _dbContext.Sizes.ToList();
                model.Colors = _dbContext.Colors.ToList();
                ModelState.AddModelError("ColorIds", "Color not found");
                return View(model);
            }

            var productColor = new ProductColor
            {
                ColorId = color.Id,
                Product = product,
            };

            _dbContext.ProductColors.Add(productColor);
        }

        #endregion

        _dbContext.SaveChanges();

        return RedirectToAction(nameof(Index));
    }


    #endregion

    #region Update

    [HttpGet("{id}/update")]
    public IActionResult Update(int id)
    {
        var product = _dbContext.Products.FirstOrDefault(p => p.Id == id);
        if (product == null) return NotFound();

        var selectedCategoryIds = _dbContext.CategoryProducts
            .Where(cp => cp.ProductId == product.Id)
            .Select(cp => cp.CategoryId)
            .ToArray();

        var model = new ProductUpdateViewModel
        {
            Id = product.Id,
            Name = product.Name,
            Description = product.Description,
            Color = default,
            Size = default,
            Price = product.Price,
            CategoryIds = selectedCategoryIds,
            Categories = _dbContext.Categories.ToList(),
            CurrentFileName = product.PhysicalImageName
        };

        return View(model);
    }

    [HttpPost("{id}/update")]
    public IActionResult Update(ProductUpdateViewModel model)
    {
        if (!ModelState.IsValid)
        {
            model.Categories = _dbContext.Categories.ToList();
            return View(model);
        }

        var product = _dbContext.Products.FirstOrDefault(p => p.Id == model.Id);
        if (product == null)
        {
            ModelState.AddModelError("Name", "Product not found");
            model.Categories = _dbContext.Categories.ToList();
            return View(model);
        }

        var previousFileName = product.PhysicalImageName;

        var path = _fileService
            .GetStaticFilesDirectory(CustomUploadDirectories.Products);

        if (model.Image != null)
        {
            product.PhysicalImageName = _fileService.Upload(model.Image, CustomUploadDirectories.Products);
        }

        product.Name = model.Name;
        product.Description = model.Description;
        //product.Color = default;
        product.Price = model.Price;

        _dbContext.Products.Update(product);

        if (model.Image != null && previousFileName != null)
        {
            var previousFullPath = _fileService
                .GetStaticFilesDirectory(CustomUploadDirectories.Products, previousFileName);

            System.IO.File.Delete(previousFullPath);
        }

        var removeableProductCategories = _dbContext.CategoryProducts
            .Where(cp =>
                cp.ProductId == product.Id &&
                !model.CategoryIds.Contains(cp.CategoryId))
            .ToList();

        var addableCategoryIds = model.CategoryIds
            .Where(id => !_dbContext.CategoryProducts
                .Where(cp => cp.ProductId == product.Id)
                .Any(cp => cp.CategoryId == id))
            .ToList();

        var addableProductCategories = addableCategoryIds.Select(id => new CategoryProduct
        {
            CategoryId = id,
            ProductId = product.Id,
        });

        _dbContext.CategoryProducts.RemoveRange(removeableProductCategories);
        _dbContext.CategoryProducts.AddRange(addableProductCategories);

        _dbContext.SaveChanges();

        return RedirectToAction(nameof(Index));
    }

    #endregion

    #region Delete

    [HttpPost("{id}/delete")]
    public IActionResult Delete(int id)
    {
        var product = _dbContext.Products.FirstOrDefault(p => p.Id == id);
        if (product == null) return NotFound();

        _dbContext.Remove(product);
        _dbContext.SaveChanges();

        return RedirectToAction(nameof(Index));
    }

    #endregion
}
