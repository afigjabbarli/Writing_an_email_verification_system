using MailKit.Net.Smtp;
using Microsoft.Extensions.Configuration;
using MimeKit;
using Pustok.Contracts;
using Pustok.Services.Abstracts;

namespace Pustok.Services.Concretes
{
    public class MailkitEmailService : IEmailService
    {
        private readonly string _userName;
        private readonly string _email;
        private readonly string _password;
        private readonly int _port;
        private readonly string _smtpServer;

        public MailkitEmailService(IConfiguration configuration)
        {
            _userName = configuration.GetValue<string>("EmailSettings:Username");
            _email = configuration.GetValue<string>("EmailSettings:Email");
            _password = configuration.GetValue<string>("EmailSettings:Password");
            _port = configuration.GetValue<int>("EmailSettings:SmtpPort");
            _smtpServer = configuration.GetValue<string>("EmailSettings:SmtpServer");
        }

        public void SendEmail(string subject, string content, string receipent)
        {
            var messageDto = new MessageDto
            {
                Subject = subject,
                Content = content,
                Receipents = new List<string> { receipent }
            };

            SendEmail(messageDto);
        }
        public void SendEmail(string subject, string content, params string[] receipents)
        {
            var messageDto = new MessageDto
            {
                Subject = subject,
                Content = content,
                Receipents = receipents.ToList()
            };

            SendEmail(messageDto);
        }
        public void SendEmail(MessageDto messageDto)
        {
            var emailMessage = CreateEmailMessage(messageDto);
            AuthorizeAndSend(emailMessage);
        }

        private MimeMessage CreateEmailMessage(MessageDto messageDto)
        {
            var emailMessage = new MimeMessage();

            emailMessage.Subject = messageDto.Subject;
            emailMessage.Body = new TextPart(MimeKit.Text.TextFormat.Text) { Text = messageDto.Content };

            emailMessage.From.Add(new MailboxAddress(_userName, _email));
            emailMessage.To.AddRange(messageDto.Receipents.Select(r => new MailboxAddress(r, r)));

            return emailMessage;
        }
        private void AuthorizeAndSend(MimeMessage mailMessage)
        {
            var client = new SmtpClient();

            try
            {
                client.Connect(_smtpServer, _port, false);
                client.AuthenticationMechanisms.Remove("XOAUTH2");
                client.Authenticate(_email, _password);

                client.Send(mailMessage);
            }
            catch
            {
                throw;
            }
            finally
            {
                client.Disconnect(true);
                client.Dispose();
            }
        }
    }
}
