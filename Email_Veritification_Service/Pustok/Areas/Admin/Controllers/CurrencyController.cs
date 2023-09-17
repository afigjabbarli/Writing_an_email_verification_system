using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Pustok.Contracts;
using Pustok.Helpers;

namespace Pustok.Areas.Admin.Controllers;

[Area("admin")]
[Authorize(Roles = Role.Names.SuperAdmin)]
[Route("admin/currencies")]
public class CurrencyController : Controller
{
    private IHttpClientFactory _httpClientFactory;
    private readonly IConfiguration _configuration;
    private readonly ILogger<CurrencyController> _logger;

    public CurrencyController(
        IHttpClientFactory httpClientFactory, IConfiguration configuration, ILogger<CurrencyController> logger)
    {
        _httpClientFactory = httpClientFactory;
        _configuration = configuration;
        _logger = logger;
    }

    [HttpGet]
    public async Task<IActionResult> List()
    {
        _logger.LogWarning("===========Request to endpoint started");

        var httpClient = _httpClientFactory.CreateClient();
        var apiBase = _configuration.GetSection("CurrencyApiBase").Value;
        var apiKey = _configuration.GetSection("CurrencyApiKey").Value;

        var uriBuilder = new UrlBuilder(apiBase);
        var endpoint = uriBuilder
            .AddQuery("access_key", apiKey)
            .Build();

        var currencyResult = await httpClient.GetFromJsonAsync<CurrencyResult>(endpoint);

        _logger.LogWarning("============Request to endpoint completed");

        return View(currencyResult);
    }
}
