using Novell.Directory.Ldap;
using System.Linq;

namespace LDAPAuth
{
    public class LDAPAuthenticator
    {
        private const string MemberOfAttribute = "memberOf";
        private const string DisplayNameAttribute = "displayName";
        private const string SAMAccountNameAttribute = "sAMAccountName";

        public LDAPUser ValidateUser(string domainName, string username, string password)
        {
            try
            {
                string userDn = $"{username}@{domainName}";

                using (var connection = new LdapConnection { SecureSocketLayer = false })
                {
                    connection.Connect(domainName, LdapConnection.DEFAULT_PORT);
                    connection.Bind(userDn, password);

                    if (connection.Bound)
                    {
                        var searchBase = GetSearchBase(domainName);
                        var searchFilter = string.Format("(&(objectClass=user)(objectClass=person)(sAMAccountName={0}))", username);

                        var result = connection.Search(searchBase, LdapConnection.SCOPE_SUB, searchFilter, new[] { MemberOfAttribute, DisplayNameAttribute, SAMAccountNameAttribute }, false);

                        var user = result.Next();

                        if (user != null)
                        {
                            var displayName = user.getAttribute(DisplayNameAttribute).StringValue;
                            var accountName = user.getAttribute(SAMAccountNameAttribute).StringValue;
                            var memberOf = user.getAttribute(MemberOfAttribute).StringValueArray.SelectMany(x => x.Split(',').Where(w => w.StartsWith("CN=")).Select(s => s.Substring(3)));

                            return new LDAPUser
                            {
                                AccountName = accountName,
                                DisplayName = displayName,
                                MemberOf = memberOf
                            };
                        }
                    }
                }
            }
            catch (LdapException)
            {

            }

            return null;
        }

        private string GetSearchBase(string domainName)
        {
            var parts = domainName.Split('.');

            return string.Join(",", parts.Select(x => $"DC={x}"));
        }
    }
}
