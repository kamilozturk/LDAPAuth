﻿using LDAPAuth;
using System;

namespace DotnetCoreLDAPAuth
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Login on Active Directory!");

            Console.Write("Domain: ");
            var domain = Console.ReadLine();

            Console.Write("Username: ");
            var username = Console.ReadLine();

            Console.Write("Password: ");
            var password = Console.ReadLine();

            var auth = new LDAPAuthenticator();

            var user = auth.ValidateUser(domain, username, password);

            if (user != null)
            {
                Console.WriteLine("User Authenticated!");
                Console.WriteLine($"Full Name: {user.DisplayName}");
                Console.WriteLine($"Account Name: {user.AccountName}");
                Console.WriteLine($"Member Of: {string.Join('\n', user.MemberOf)}");
            }
            else
            {
                Console.WriteLine("User Not Authenticated!");
            }

            Console.Read();
        }
    }


}