//using Microsoft.AspNetCore.Mvc;
//using Pustok.Database.Models;
//using Pustok.Database.Repositories;

//namespace Pustok.Controllers;

//public class BookController : Controller
//{
//    private readonly BookRepository _bookRepository;

//    public BookController()
//    {
//        _bookRepository = new BookRepository();
//    }

//    [HttpGet]
//    public IActionResult Index()
//    {
//        var books = _bookRepository.GetAll();
//        var result = View(books);
//        return result;
//    }

//    #region Add

//    [HttpGet]
//    public IActionResult Add()
//    {
//        return View();
//    }

//    [HttpPost]
//    public IActionResult Add(string title, string description, string author, decimal price)
//    {
//        var book = new Book(title, description, author, price, DateTime.Now);
//        _bookRepository.Insert(book);

//        return RedirectToAction(nameof(Index));
//    }

//    #endregion

//    #region Update

//    [HttpGet]
//    public IActionResult Update(int id)
//    {
//        var book = _bookRepository.GetById(id);
//        if (book == null) return NotFound();

//        return View(book);
//    }

//    [HttpPost]
//    //TODO : id from query params
//    public IActionResult Update(int id, string title, string description, string author, decimal price)
//    {
//        var book = _bookRepository.GetById(id);
//        if (book == null) return NotFound();

//        book.Title = title;
//        book.Description = description;
//        book.Author = author;
//        book.Price = price;

//        return RedirectToAction(nameof(Index));
//    }

//    #endregion

//    #region Delete

//    [HttpPost]
//    public IActionResult Delete(int id)
//    {
//        var book = _bookRepository.GetById(id);
//        if (book == null) return NotFound();

//        _bookRepository.RemoveById(id);

//        return RedirectToAction(nameof(Index));
//    }

//    #endregion
//}
