namespace Pustok.Contracts;

public class MessageDto
{
    public MessageDto() { }

    public MessageDto(string subject, string content, List<string> receipents)
    {
        Subject = subject;
        Content = content;
        Receipents = receipents;
    }

    //public MessageDto(string subject, string content, List<MailboxAddress> receipents)
    //{
    //    Subject = subject;
    //    Content = content;
    //    Receipents = receipents;
    //}

    public string Subject { get; set; }
    public string Content { get; set; }
    //public List<MailboxAddress> Receipents { get; set; } = new List<MailboxAddress>();
    public List<string> Receipents { get; set; }
}
