namespace Pustok.Contracts;

public class Role
{
    public enum Values
    {
        User = 0,
        Admin = 1,
        Moderator = 2,
        SuperAdmin = 4
    }

    public class Names
    {
        public const string User = "User";
        public const string Admin = "Admin";
        public const string Moderator = "Moderator";
        public const string SuperAdmin = "SuperAdmin";
    }
}
