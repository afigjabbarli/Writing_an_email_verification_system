using Pustok.Database.Models;

namespace Pustok.Services.Abstracts
{
    public interface IVerificationService
    {
        string GenerateRandomVerificationToken();

        void SendAccountActivationURL(User activatedUser, int ID, string token);
    }
}
