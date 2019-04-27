namespace netCore_Console
{
    using System.Collections.Generic;

    public class People
    {
        public List<Name> names;
        public List<PhoneNumber> phoneNumbers;
        public string etag = null;
        public string resourceName = null;
        public List<Url> urls;
    }
    public class Name
    {
        public string givenName;
    }
    public class PhoneNumber
    {
        public string value;
        public string type = "Outro";
    }
    public class Url
    {
        public string value;
        public string type = "Observação";
    }

}