using System;
using System.Collections.Generic;
using Newtonsoft.Json;

namespace netCore_Console
{
    class Program
    {
        static void Main(string[] args)
        {
            string clienteID = "";
            string clienteSecret = "";
            string refreshToken = "";
            Console.WriteLine("People API");
            PeopleAPI primeiroAcesso = new PeopleAPI(clienteID, clienteSecret);
            PeopleAPI segundoAcesso = new PeopleAPI(clienteID, clienteSecret, refreshToken);
        }
    }
}
