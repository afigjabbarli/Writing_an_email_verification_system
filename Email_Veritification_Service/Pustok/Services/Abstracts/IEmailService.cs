using Pustok.Contracts;

namespace Pustok.Services.Abstracts;

public interface IEmailService
{
    void SendEmail(string subject, string content, string receipent);
    void SendEmail(string subject, string content, params string[] receipents);
    void SendEmail(MessageDto messageDto);
}
