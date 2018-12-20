using Novell.Directory.Ldap;
using System.Collections.Generic;
using System.Linq;

namespace LDAPAuth
{
    public class LDAPAuthenticator
    {
        private const string MemberOfAttribute = "memberOf";
        private const string DisplayNameAttribute = "displayName";
        private const string SAMAccountNameAttribute = "sAMAccountName";
        private const string MailAttribute = "mail";

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

        public List<LDAPUser> SearchUser(string domainName, string username, string password, string searchName, int maxResult)
        {
            var list = new List<LDAPUser>();

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
                        var searchFilter = string.Format("(&(objectClass=user)(objectClass=person)(displayName=*{0}*))", searchName);

                        var result = connection.Search(searchBase, LdapConnection.SCOPE_SUB, searchFilter, new[] { MemberOfAttribute, DisplayNameAttribute, SAMAccountNameAttribute, MailAttribute }, false,
                            new LdapSearchConstraints(0, 0, 0, maxResult, true, maxResult, null, 0));

                        while (result.HasMore())
                        {
                            var user = result.Next();
                            var displayName = user.getAttribute(DisplayNameAttribute)?.StringValue;
                            var accountName = user.getAttribute(SAMAccountNameAttribute)?.StringValue;
                            var email = user.getAttribute(MailAttribute)?.StringValue;
                            var memberOf = user.getAttribute(MemberOfAttribute)?.StringValueArray?.SelectMany(x => x.Split(',').Where(w => w.StartsWith("CN=")).Select(s => s.Substring(3)));

                            var luser = new LDAPUser
                            {
                                AccountName = accountName,
                                DisplayName = displayName,
                                Email = email,
                                MemberOf = memberOf ?? new List<string>()
                            };

                            list.Add(luser);
                        }
                    }
                }
            }
            catch (LdapException)
            {

            }

            return list;
        }

        private string GetSearchBase(string domainName)
        {
            var parts = domainName.Split('.');

            return string.Join(",", parts.Select(x => $"DC={x}"));
        }
    }
}
