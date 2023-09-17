using Pustok.ViewModels;

namespace Pustok.Services.Abstracts;

public interface IBasketService
{
    public void AddToBasket(int productId, int colorId, int sizeId, int? quantity);
    List<BasketCookieItemViewModel> GetBasketItemsFromCookie();
    void ClearBasket();
}
