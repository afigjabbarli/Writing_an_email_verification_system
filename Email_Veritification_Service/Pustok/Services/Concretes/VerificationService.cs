using Pustok.Contracts;
using Pustok.Database.Models;
using Pustok.Services.Abstracts;

namespace Pustok.Services.Concretes
{
    public class VerificationService : IVerificationService
    {
        private readonly IConfiguration _configuration; 
        private readonly IEmailService _emailService;
        public VerificationService(IConfiguration configuration, IEmailService emailService)
        {
            _configuration = configuration;
            _emailService = emailService;
        }
        public string GenerateRandomVerificationToken()
        {
            Guid guid = Guid.NewGuid();
            string token = guid.ToString();
            return token;
        }

        public void SendAccountActivationURL(User activatedUser, int ID, string token)
        {
            var messageDto = new MessageDto()
            {

                Subject = "Confirmation of Register",
                Content = $"Hello dear {activatedUser.LastName + activatedUser.Name}, You can activate your account by entering the link: " + _configuration["Server"] + "Auth/Verify" + $"?ID={ID}" + $"&token={token}",
                Receipents = new List<string> { activatedUser.Email }
            };
            _emailService.SendEmail(messageDto);
        }
    }
}
