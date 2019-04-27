using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using Newtonsoft.Json.Linq;
using System.Collections;
using System.Runtime.InteropServices;
using System.Web;

namespace netCore_Console
{
    class PeopleAPI
    {
        private string ClientID;
        private string ClientSecret;
        private string AccessToken;
        private string RefreshToken;

        private const string authorizationEndpoint = "https://accounts.google.com/o/oauth2/v2/auth";
        private const string tokenEndpoint = "https://www.googleapis.com/oauth2/v4/token";
        private const string userInfoEndpoint = "https://www.googleapis.com/oauth2/v3/userinfo";
        public PeopleAPI(string clientID, string clientSecret, string refreshToken = "")
        {
            ClientID = clientID;
            ClientSecret = clientSecret;
            if (refreshToken != "")
            {
                this.RefreshToken = refreshToken;
            }
            else
            {
                doOAuth();
            }
        }

        private void doOAuth()
        {
            // Generates state and PKCE values.
            string state = randomDataBase64url(32);
            string code_verifier = randomDataBase64url(32);
            string code_challenge = base64urlencodeNoPadding(sha256(code_verifier));
            const string code_challenge_method = "S256";

            // Creates a redirect URI using an available port on the loopback address.
            string redirectURI = string.Format("http://{0}:{1}/", IPAddress.Loopback, GetRandomUnusedPort());
            Output("redirect URI: " + redirectURI);

            // Creates an HttpListener to listen for requests on that redirect URI.
            var http = new HttpListener();
            http.Prefixes.Add(redirectURI);
            Output("Listening..");
            http.Start();

            // Creates the OAuth 2.0 authorization request.
            string authorizationRequest = string.Format("{0}?response_type=code&scope={6}&redirect_uri={1}&client_id={2}&state={3}&code_challenge={4}&code_challenge_method={5}",
                                                           authorizationEndpoint,
                                                           Uri.EscapeDataString(redirectURI),
                                                           ClientID,
                                                           state,
                                                           code_challenge,
                                                           code_challenge_method,
                                                           HttpUtility.UrlEncode("openid profile https://www.googleapis.com/auth/contacts"));

            // Opens request in the browser.
            OpenBrowser(authorizationRequest);

            // Waits for the OAuth authorization response.
            var context = http.GetContext();

            // Sends an HTTP response to the browser.
            var response = context.Response;
            string responseString = string.Format("<html><head><meta http-equiv='refresh' content='10;url=https://google.com'></head><body>Please return to the app.</body></html>");
            var buffer = System.Text.Encoding.UTF8.GetBytes(responseString);
            response.ContentLength64 = buffer.Length;
            var responseOutput = response.OutputStream;
            Task responseTask = responseOutput.WriteAsync(buffer, 0, buffer.Length).ContinueWith((task) =>
            {
                responseOutput.Close();
                http.Stop();
                Console.WriteLine("HTTP server stopped.");
            });

            // Checks for errors.
            if (context.Request.QueryString.Get("error") != null)
            {
                Output(String.Format("OAuth authorization error: {0}.", context.Request.QueryString.Get("error")));
                return;
            }
            if (context.Request.QueryString.Get("code") == null
                || context.Request.QueryString.Get("state") == null)
            {
                Output("Malformed authorization response. " + context.Request.QueryString);
                return;
            }

            // extracts the code
            var code = context.Request.QueryString.Get("code");
            var incoming_state = context.Request.QueryString.Get("state");

            // Compares the receieved state to the expected value, to ensure that
            // this app made the request which resulted in authorization.
            if (incoming_state != state)
            {
                Output(String.Format("Received request with invalid state ({0})", incoming_state));
                return;
            }
            Output("Authorization code: " + code);

            // Starts the code exchange at the Token Endpoint.
            PerformCodeExchange(code, code_verifier, redirectURI);
        }

        private void PerformCodeExchange(string code, string code_verifier, string redirectURI)
        {
            Output("Exchanging code for tokens...");
            string tokenRequestURI = "https://www.googleapis.com/oauth2/v4/token";
            string tokenRequestBody = string.Format("code={0}&redirect_uri={1}&client_id={2}&code_verifier={3}&client_secret={4}&scope=&grant_type=authorization_code", code, Uri.EscapeDataString(redirectURI), ClientID, code_verifier, ClientSecret);
            HttpWebRequest tokenRequest = (HttpWebRequest)WebRequest.Create(tokenRequestURI);
            tokenRequest.Method = "POST";
            tokenRequest.ContentType = "application/x-www-form-urlencoded";
            tokenRequest.Accept = "Accept=text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
            byte[] _byteVersion = Encoding.ASCII.GetBytes(tokenRequestBody);
            tokenRequest.ContentLength = _byteVersion.Length;
            Stream stream = tokenRequest.GetRequestStream();
            stream.Write(_byteVersion, 0, _byteVersion.Length);
            stream.Close();

            WebResponse tokenResponse = tokenRequest.GetResponse();

            using (StreamReader reader = new StreamReader(tokenResponse.GetResponseStream()))
            {
                string responseText = reader.ReadToEnd();
                Console.WriteLine(responseText);
                Dictionary<string, string> tokenEndpointDecoded = JsonConvert.DeserializeObject<Dictionary<string, string>>(responseText);
                AccessToken = tokenEndpointDecoded["access_token"];
                RefreshToken = tokenEndpointDecoded["refresh_token"];
            }
        }
        private void RefreshingToken()
        {
            Output("Refeshing token...");
            string tokenRequestURI = "https://www.googleapis.com/oauth2/v4/token";
            string tokenRequestBody = String.Format("client_id={0}&client_secret={1}&refresh_token={2}&grant_type=refresh_token",
                                                           ClientID,
                                                           ClientSecret,
                                                           RefreshToken);
            HttpWebRequest tokenRequest = (HttpWebRequest)WebRequest.Create(tokenRequestURI);
            tokenRequest.Method = "POST";
            tokenRequest.ContentType = "application/x-www-form-urlencoded";
            tokenRequest.Accept = "Accept=text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
            byte[] _byteVersion = Encoding.ASCII.GetBytes(tokenRequestBody);
            tokenRequest.ContentLength = _byteVersion.Length;
            Stream stream = tokenRequest.GetRequestStream();
            stream.Write(_byteVersion, 0, _byteVersion.Length);
            stream.Close();

            WebResponse tokenResponse = tokenRequest.GetResponse();

            using (StreamReader reader = new StreamReader(tokenResponse.GetResponseStream()))
            {
                string responseText = reader.ReadToEnd();
                Console.WriteLine(responseText);
                Dictionary<string, string> tokenEndpointDecoded = JsonConvert.DeserializeObject<Dictionary<string, string>>(responseText);
                AccessToken = tokenEndpointDecoded["access_token"];
            }
        }

        public void userinfoCall()
        {
            RefreshingToken();
            try
            {
                string userinfoRequestURI = "https://www.googleapis.com/oauth2/v3/userinfo";
                HttpWebRequest userinfoRequest = (HttpWebRequest)WebRequest.Create(userinfoRequestURI);
                userinfoRequest.Method = "GET";
                userinfoRequest.Headers.Add(string.Format("Authorization: Bearer {0}", AccessToken));
                userinfoRequest.ContentType = "application/x-www-form-urlencoded";
                userinfoRequest.Accept = "Accept=text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
                WebResponse userinfoResponse = userinfoRequest.GetResponse();

                using (StreamReader userinfoResponseReader = new StreamReader(userinfoResponse.GetResponseStream()))
                {
                    string userinfoResponseText = userinfoResponseReader.ReadToEnd();
                    Output(userinfoResponseText);
                }
            }
            catch (WebException ex)
            {
                if (ex.Status == WebExceptionStatus.ProtocolError)
                {
                    var response = ex.Response as HttpWebResponse;

                    if (response != null)
                    {
                        Output("HTTP: " + response.StatusCode);

                        using (StreamReader reader = new StreamReader(response.GetResponseStream()))
                        {
                            string responseText = reader.ReadToEnd();
                            Output(responseText);
                        }
                    }
                }
            }
        }

        #region "CRUD"
        public void CreateContact(People contact)
        {
            RefreshingToken();
            try
            {
                string requestURI = string.Format("https://people.googleapis.com/v1/people:createContact?fields={0}", WebUtility.UrlEncode("names/givenName,phoneNumbers(type,value),urls(type,value)"));
                string requestBody = JsonConvert.SerializeObject(contact);
                HttpWebRequest request = (HttpWebRequest)WebRequest.Create(requestURI);
                request.Method = "POST";
                request.Headers.Add(string.Format("Authorization: Bearer {0}", AccessToken));
                request.ContentType = "application/json; charset=UTF-8";
                request.Accept = "Accept=text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
                byte[] _byteVersion = Encoding.UTF8.GetBytes(requestBody);
                request.ContentLength = _byteVersion.Length;
                Stream stream = request.GetRequestStream();
                stream.Write(_byteVersion, 0, _byteVersion.Length);
                stream.Close();
                WebResponse tokenResponse = request.GetResponse();

                using (StreamReader reader = new StreamReader(tokenResponse.GetResponseStream()))
                {
                    string responseText = reader.ReadToEnd();
                    Output(responseText);
                }
            }
            catch (WebException ex)
            {
                if (ex.Status == WebExceptionStatus.ProtocolError)
                {
                    var response = ex.Response as HttpWebResponse;

                    if (response != null)
                    {
                        Output("HTTP: " + response.StatusCode);

                        using (StreamReader reader = new StreamReader(response.GetResponseStream()))
                        {
                            Output(reader.ReadToEnd());
                        }
                    }
                }
            }
        }

        public void UpdateContact(People contact)
        {
            RefreshingToken();
            try
            {
                string requestURI = string.Format("https://people.googleapis.com/v1/{0}:updateContact?updatePersonFields={1}", contact.resourceName, WebUtility.UrlEncode("names,phoneNumbers,urls"));
                string requestBody = JsonConvert.SerializeObject(contact);
                HttpWebRequest request = (HttpWebRequest)WebRequest.Create(requestURI);
                request.Method = "PATCH";
                request.Headers.Add(string.Format("Authorization: Bearer {0}", AccessToken));
                request.ContentType = "application/json; charset=UTF-8";
                request.Accept = "Accept=text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
                byte[] _byteVersion = Encoding.UTF8.GetBytes(requestBody);
                request.ContentLength = _byteVersion.Length;
                Stream stream = request.GetRequestStream();
                stream.Write(_byteVersion, 0, _byteVersion.Length);
                stream.Close();
                WebResponse tokenResponse = request.GetResponse();

                using (StreamReader reader = new StreamReader(tokenResponse.GetResponseStream()))
                {
                    string responseText = reader.ReadToEnd();
                    Output(responseText);
                }
            }
            catch (WebException ex)
            {
                if (ex.Status == WebExceptionStatus.ProtocolError)
                {
                    var response = ex.Response as HttpWebResponse;

                    if (response != null)
                    {
                        Output("HTTP: " + response.StatusCode);

                        using (StreamReader reader = new StreamReader(response.GetResponseStream()))
                        {
                            string responseText = reader.ReadToEnd();
                            Output(responseText);
                        }
                    }
                }
            }
        }

        public void GetAllContacts(string path)
        {
            string contatosJson;
            try
            {
                contatosJson = JsonConvert.SerializeObject(GetAllContacts());
            }
            catch (JsonSerializationException ex)
            {
                contatosJson = "Erro ao fazer a serialização para gerar o jsonFile: " + ex.Message;
            }
            catch (Exception ex)
            {
                contatosJson = "Ocorreu um erro: " + ex.Message;
            }
            File.WriteAllText(path, contatosJson);
        }
        public IEnumerable<JToken> GetAllContacts()
        {
            RefreshingToken();
            IList<JToken> contacts = new List<JToken>();
            string nextPageToken = "";
            try
            {
                do
                {
                    string requestURI = String.Format("https://people.googleapis.com/v1/people/me/connections?pageSize={0}&personFields={1}&pageToken={2}",
                                                             "2000",
                                                             "names,phoneNumbers,urls",
                                                             nextPageToken);
                    HttpWebRequest listRequest = (HttpWebRequest)WebRequest.Create(requestURI);
                    listRequest.Method = "GET";
                    listRequest.Headers.Add(String.Format("Authorization: Bearer {0}", AccessToken));
                    listRequest.ContentType = "application/x-www-form-urlencoded";
                    listRequest.Accept = "Accept=text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
                    WebResponse listResponse = listRequest.GetResponse();
                    using (StreamReader listResponseHeader = new StreamReader(listResponse.GetResponseStream()))
                    {
                        JObject listResponseText = JObject.Parse(listResponseHeader.ReadToEnd());
                        if (listResponseText.ToString() == "{}")
                            return contacts;
                        else
                            foreach (JToken contact in listResponseText["connections"])
                                contacts.Add(contact);
                        nextPageToken = Convert.ToString(listResponseText["nextPageToken"]);
                    }
                } while (!String.IsNullOrEmpty(nextPageToken));
            }
            catch (WebException ex)
            {
                if (ex.Status == WebExceptionStatus.ProtocolError)
                {
                    var response = ex.Response as HttpWebResponse;
                    if (response != null)
                    {
                        Output("HTTP: " + response.StatusCode);
                        using (StreamReader reader = new StreamReader(response.GetResponseStream()))
                        {
                            Output(reader.ReadToEnd());
                        }
                    }
                }
            }
            return contacts;
        }

        public JToken GetContact(string resourceName)
        {
            RefreshingToken();
            JToken contact = "";
            try
            {
                string requestURI = string.Format("https://people.googleapis.com/v1/{0}?personFields={1}",
                                                         resourceName,
                                                         "names,phoneNumbers,urls");
                HttpWebRequest request = (HttpWebRequest)WebRequest.Create(requestURI);
                request.Method = "GET";
                request.Headers.Add(string.Format("Authorization: Bearer {0}", AccessToken));
                request.ContentType = "application/json; charset=UTF-8";
                request.Accept = "Accept=text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
                WebResponse listResponse = request.GetResponse();
                using (StreamReader listResponseHeader = new StreamReader(listResponse.GetResponseStream()))
                {
                    contact = JObject.Parse(listResponseHeader.ReadToEnd());
                }
            }
            catch (WebException ex)
            {
                if (ex.Status == WebExceptionStatus.ProtocolError)
                {
                    var response = ex.Response as HttpWebResponse;

                    if (response != null)
                    {
                        Output("HTTP: " + response.StatusCode);
                        using (StreamReader reader = new StreamReader(response.GetResponseStream()))
                        {
                            Output(reader.ReadToEnd());
                        }
                    }
                }
            }
            return contact;
        }

        public void DeleteContact(string resourceName)
        {
            try
            {
                string requestURI = string.Format("https://people.googleapis.com/v1/{0}:deleteContact", resourceName);
                HttpWebRequest request = (HttpWebRequest)WebRequest.Create(requestURI);
                request.Method = "DELETE";
                request.Headers.Add(string.Format("Authorization: Bearer {0}", AccessToken));
                request.ContentType = "application/json; charset=UTF-8";
                request.Accept = "Accept=text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
                WebResponse tokenResponse = request.GetResponse();

                using (StreamReader reader = new StreamReader(tokenResponse.GetResponseStream()))
                {
                    string responseText = reader.ReadToEnd();
                    Output(responseText);
                }
            }
            catch (WebException ex)
            {
                if (ex.Status == WebExceptionStatus.ProtocolError)
                {
                    var response = ex.Response as HttpWebResponse;

                    if (response != null)
                    {
                        Output("HTTP: " + response.StatusCode);

                        using (StreamReader reader = new StreamReader(response.GetResponseStream()))
                        {
                            Output(reader.ReadToEnd());
                        }
                    }
                }
            }
        }

        #endregion

        #region "Outros"
        public static int GetRandomUnusedPort()
        {
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            var port = ((IPEndPoint)listener.LocalEndpoint).Port;
            listener.Stop();
            return port;
        }
        public void Output(string Output) => Console.WriteLine(Output);

        /// <summary>
        /// Returns URI-safe data with a given input length.
        /// </summary>
        /// <param name="length">Input length (nb. Output will be longer)</param>
        /// <returns></returns>
        public static string randomDataBase64url(uint length)
        {
            RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
            byte[] bytes = new byte[length];
            rng.GetBytes(bytes);
            return base64urlencodeNoPadding(bytes);
        }

        /// <summary>
        /// Returns the SHA256 hash of the input string.
        /// </summary>
        /// <param name="inputStirng"></param>
        /// <returns></returns>
        public static byte[] sha256(string inputStirng)
        {
            byte[] bytes = Encoding.ASCII.GetBytes(inputStirng);
            SHA256Managed sha256 = new SHA256Managed();
            return sha256.ComputeHash(bytes);
        }

        /// <summary>
        /// Base64url no-padding encodes the given input buffer.
        /// </summary>
        /// <param name="buffer"></param>
        /// <returns></returns>
        public static string base64urlencodeNoPadding(byte[] buffer)
        {
            string base64 = Convert.ToBase64String(buffer);

            // Converts base64 to base64url.
            base64 = base64.Replace("+", "-");
            base64 = base64.Replace("/", "_");
            // Strips padding.
            base64 = base64.Replace("=", "");

            return base64;
        }

        public static void OpenBrowser(string url)
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                Process.Start(new ProcessStartInfo("cmd", $"/c start {url}")); // Works ok on windows
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                Process.Start("xdg-open", url);  // Works ok on linux
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                Process.Start("open", url); // Not tested
            }
        }
        #endregion
    }
}