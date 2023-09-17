using Pustok.Contracts;
using Pustok.Database.Models;
using Pustok.Services.Abstracts;
using Pustok.ViewModels;
using System.Text.Json;

namespace Pustok.Services.Concretes;

public class BasketService : IBasketService
{
    private readonly IHttpContextAccessor _httpContextAccessor;

    public BasketService(IHttpContextAccessor httpContextAccessor)
    {
        _httpContextAccessor = httpContextAccessor;
    }

    public void AddToBasket(int productId, int colorId, int sizeId, int? quantity)
    {
        var basketItemCookieViewModels = new List<BasketCookieItemViewModel>();
        var basketItemCookieViewModel = new BasketCookieItemViewModel();

        var cookieValue = _httpContextAccessor.HttpContext.Request.Cookies[CookieNames.BASKET_ITEMS];
        if (cookieValue != null)
        {
            basketItemCookieViewModels = JsonSerializer.Deserialize<List<BasketCookieItemViewModel>>(cookieValue);
            basketItemCookieViewModel = GetBasketItem(basketItemCookieViewModels, productId, colorId, sizeId);

            if (basketItemCookieViewModel != null)
            {
                UpdateBasketItemQuantity(basketItemCookieViewModel, quantity);
            }
            else
            {
                basketItemCookieViewModel = InitializerNewBasketItem(productId, colorId, sizeId, quantity);
                basketItemCookieViewModels.Add(basketItemCookieViewModel);
            }

        }
        else
        {
            basketItemCookieViewModel = InitializerNewBasketItem(productId, colorId, sizeId, quantity);
            basketItemCookieViewModels.Add(basketItemCookieViewModel);
        }

        cookieValue = JsonSerializer.Serialize(basketItemCookieViewModels);

        _httpContextAccessor.HttpContext.Response.Cookies.Append(CookieNames.BASKET_ITEMS, cookieValue);
    }


    private BasketCookieItemViewModel InitializerNewBasketItem(int productId, int colorId, int sizeId, int? quantity)
    {
        return new BasketCookieItemViewModel
        {
            ProductId = productId,
            ColorId = colorId,
            SizeId = sizeId,
            Quantity = quantity ?? 1
        };
    }

    private void UpdateBasketItemQuantity(BasketCookieItemViewModel model, int? quantity)
    {
        model.Quantity += (quantity ?? 1);
    }

    private BasketCookieItemViewModel GetBasketItem(List<BasketCookieItemViewModel> basketCookieItemViewModels, int productId, int colorId, int sizeId)
    {
        return basketCookieItemViewModels.FirstOrDefault(m =>
            m.ProductId == productId &&
            m.SizeId == sizeId &&
            m.ColorId == colorId);
    }

    public List<BasketCookieItemViewModel> GetBasketItemsFromCookie()
    {
        var cookieValue = _httpContextAccessor.HttpContext.Request.Cookies[CookieNames.BASKET_ITEMS];

        return cookieValue != null ? 
            JsonSerializer.Deserialize<List<BasketCookieItemViewModel>>(cookieValue) : 
            new List<BasketCookieItemViewModel>();
    }

    public void ClearBasket()
    {
        _httpContextAccessor.HttpContext.Response.Cookies.Delete(CookieNames.BASKET_ITEMS);
    }
}
