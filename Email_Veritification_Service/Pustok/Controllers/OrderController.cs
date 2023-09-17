using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Pustok.Contracts;
using Pustok.Database;
using Pustok.Database.Models;
using Pustok.Services.Abstracts;
using Pustok.Services.Concretes;
using Pustok.ViewModels;

namespace Pustok.Controllers
{
    [Route("order")]
    [Authorize]
    public class OrderController : Controller
    {

        [HttpPost("place-order")]
        public IActionResult PlaceOrder(
            [FromServices] PustokDbContext pustokDbContext,
            [FromServices] IUserService userService,
            [FromServices] IOrderService orderService,
            [FromServices] IFileService fileService,
            [FromServices] IBasketService basketService )
        {
            var order = new Order
            {
                Status = OrderStatus.Created,
                TrackingCode = orderService.GenerateTrackingCode(),
                UserId = userService.CurrentUser.Id,
            };

            var basketItems = basketService.GetBasketItemsFromCookie();
            decimal total = 0;
            var orderItems= new List<OrderItem>();

            foreach (var basketItem in basketItems)
            {
                var product = pustokDbContext.Products.Single(p => p.Id == basketItem.ProductId);
                var color = pustokDbContext.Colors.Single(p => p.Id == basketItem.ColorId);
                var size = pustokDbContext.Sizes.Single(p => p.Id == basketItem.SizeId);

                var orderItem = new OrderItem
                {
                    Order = order,
                    ProductName = product.Name,
                    ProductDescription = product.Description,
                    ProductPrice = product.Price,
                    ProductOrderPhoto = fileService
                        .GetStaticFilesUrl(CustomUploadDirectories.Products, product.PhysicalImageName),
                    ProductColorName = color.Name,
                    ProductQuantity = basketItem.Quantity,
                    ProductSizeName = size.Name,
                };

                total += basketItem.Quantity * product.Price;

                orderItems.Add(orderItem);
            }

            order.OrderItems = orderItems;

            pustokDbContext.Orders.Add(order);
            pustokDbContext.SaveChanges();

            basketService.ClearBasket();

            return RedirectToAction("orders", "account");
        }
    }
}
