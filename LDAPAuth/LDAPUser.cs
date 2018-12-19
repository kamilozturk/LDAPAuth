using System.Collections.Generic;

namespace LDAPAuth
{
    public class LDAPUser
    {
        public string DisplayName { get; set; }
        public string AccountName { get; set; }
        public string Email { get; set; }
        public IEnumerable<string> MemberOf { get; set; }
    }
}
