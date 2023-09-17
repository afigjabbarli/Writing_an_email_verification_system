using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Pustok.Database;
using Pustok.Services.Abstracts;
using Pustok.Services.Concretes;
using Pustok.ViewModels;

namespace Pustok.Controllers
{
    [Route("cart")]
    [Authorize]
    public class CartController : Controller
    {
        private readonly PustokDbContext _pustokDbContext;
        private readonly IUserService _userService;
        private readonly IFileService _fileService;
        private readonly IBasketService _basketService;

        public CartController(
            PustokDbContext pustokDbContext,
            IUserService userService,
            IFileService fileService,
            IBasketService basketService)
        {
            _pustokDbContext = pustokDbContext;
            _userService = userService;
            _fileService = fileService;
            _basketService = basketService;
        }

        [HttpGet("checkout")]
        public IActionResult Index()
        {
            var basketItems = _basketService.GetBasketItemsFromCookie();
            decimal total = 0;
            var cartList = new List<CartViewModel.BasketItemViewModel>();

            foreach (var basketItem in basketItems)
            {
                var product = _pustokDbContext.Products.Single(p => p.Id == basketItem.ProductId);
                var size = _pustokDbContext.Sizes.Single(p => p.Id == basketItem.SizeId);
                var color = _pustokDbContext.Colors.Single(p => p.Id == basketItem.ColorId);

                var cart = new CartViewModel.BasketItemViewModel
                {
                    ProductName = product.Name,
                    ImageUrl = _fileService
                        .GetStaticFilesUrl(Contracts.CustomUploadDirectories.Products, product.PhysicalImageName),
                    ProductPrice = product.Price,
                    ProductId = product.Id,
                    ProductQuantity = basketItem.Quantity,
                    SizeName = size.Name,
                    ColorName = color.Name,
                };

                total += basketItem.Quantity * product.Price;

                cartList.Add(cart);
            }


            var model = new CartViewModel
            {
                BasketItems = cartList,
                Total = total
            };


            return View(model);
        }
    }
}
