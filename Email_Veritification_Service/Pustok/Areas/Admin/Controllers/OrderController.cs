using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Pustok.Areas.Admin.ViewModels.Order; // Import the necessary Order view models
using Pustok.Contracts;
using Pustok.Database;
using Pustok.Database.Models;
using Pustok.Exceptions;
using Pustok.Services.Abstracts;
using System;
using System.Linq;

namespace Pustok.Areas.Admin.Controllers
{
    [Route("admin/orders")]
    [Area("admin")]
    [Authorize(Roles = Role.Names.SuperAdmin)]
    public class OrderController : Controller
    {
        private readonly PustokDbContext _dbContext;
        private readonly IFileService _fileService;
        private readonly IUserService _userService;
        private readonly INotificationService _notificationService;

        public OrderController(PustokDbContext dbContext, IFileService fileService, IUserService userService, INotificationService notificationService)
        {
            _dbContext = dbContext;
            _fileService = fileService;
            _userService = userService;
            _notificationService = notificationService;
        }

        [HttpGet]
        public IActionResult Index()
        {
            var orderViewModels = _dbContext.Orders
                .Select(o => new OrderListItemViewModel
                {
                    Id = o.Id,
                    Status = o.Status,
                    StatusName = o.Status.ToString(),
                    TrackingCode = o.TrackingCode,
                    UserFullName = _userService.GetUserFullName(o.User),
                    CreatedAt = o.CreatedAt
                })
                .ToList();

            return View(orderViewModels);
        }


        [HttpGet("{id}/update")]
        public IActionResult Update(int id)
        {
            var order = _dbContext.Orders
                .Include(o => o.User)
                .FirstOrDefault(o => o.Id == id);
            if (order == null) return NotFound();

            var model = new OrderUpdateViewModel
            {
                Id = order.Id,
                Status = order.Status,
                TrackingCode = order.TrackingCode,
                UserFullName = _userService.GetUserFullName(order.User),
                CreatedAt = order.CreatedAt
            };

            return View(model);
        }

        [HttpPost("{id}/update")]
        public IActionResult Update(OrderUpdateViewModel model)
        {
            if (!ModelState.IsValid)
                return View();

            var order = _dbContext.Orders
                .Include(o => o.User)
                .FirstOrDefault(o => o.Id == model.Id);
            if (order == null)
            {
                return NotFound();
            }

            order.Status = model.Status;
           
            _dbContext.Orders.Update(order);
            _dbContext.SaveChanges();

            _notificationService.SendOrderNotification(order);

            return RedirectToAction(nameof(Index));
        }

        [HttpGet("{id}/items")]
        public IActionResult GetOrderItems(int id)
        {
            var orderDetailsViewModel = _dbContext.Orders
                .Include(o => o.OrderItems)
                .Include(o => o.User)
                .Where(o => o.Id == id)
                .Select(o => new OrderDetailsViewModel
                {
                    TrackingCode = o.TrackingCode,
                    OwnerFullName = _userService.GetUserFullName(o.User),
                    Items = o.OrderItems
                })
                .Single();
                

            return View(orderDetailsViewModel);
        } 
    }
}
