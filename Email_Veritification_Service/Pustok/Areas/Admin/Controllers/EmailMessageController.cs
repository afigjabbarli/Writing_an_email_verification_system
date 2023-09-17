using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Pustok.Areas.Admin.ViewModels.EmailMessage;
using Pustok.Contracts;
using Pustok.Database;
using Pustok.Database.Models;
using Pustok.Services.Abstracts;

namespace Pustok.Areas.Admin.Controllers;

[Route("admin/email-messages")] // Update route
[Area("admin")]
[Authorize(Roles = Role.Names.SuperAdmin)]
public class EmailMessageController : Controller
{
    private readonly PustokDbContext _dbContext;
    private readonly IFileService _fileService;
    private readonly IEmailService _emailService;
    private readonly IWebHostEnvironment _webHostEnvironment;
    private readonly ILogger<EmailMessageController> _logger;

    public EmailMessageController(
        PustokDbContext dbContext,
        IFileService fileService,
        IEmailService emailService,
        IWebHostEnvironment webHostEnvironment,
        ILogger<EmailMessageController> logger)
    {
        _dbContext = dbContext;
        _fileService = fileService;
        _emailService = emailService;
        _webHostEnvironment = webHostEnvironment;
        _logger = logger;
    }

    #region Index

    [HttpGet]
    public IActionResult Index()
    {
        var emailMessages = _dbContext.EmailMessages
            .OrderBy(e => e.Subject)
            .ToList();

        var emailMessageViewModels = emailMessages
            .Select(e => new EmailMessageListItemViewModel
            {
                Id = e.Id,
                Subject = e.Subject,
                SentAt = e.CreatedAt
            })
            .ToList();

        return View(emailMessageViewModels);
    }

    #endregion

    #region Add

    [HttpGet("add")]
    public IActionResult Add()
    {
        var model = new EmailMessageAddViewModel();

        return View(model);
    }

    [HttpPost("add")]
    public IActionResult Add(EmailMessageAddViewModel model)
    {
        if (!ModelState.IsValid)
        {
            return View(model);
        }

        var receipents = model.Receipents
            .Split(",")
            .ToList();

        var messageDto = new MessageDto(model.Subject, model.Content, receipents);
        _emailService.SendEmail(messageDto);

        var message = new EmailMessage
        {
            Subject = messageDto.Subject,
            Content = messageDto.Content,
            Receipents = receipents,
        };

        _dbContext.Add(message);
        _dbContext.SaveChanges();

        return RedirectToAction(nameof(Index));
    }

    #endregion
}
