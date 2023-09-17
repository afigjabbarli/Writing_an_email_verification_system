using System.Text;

namespace Pustok.Helpers
{
    public class UrlBuilder
    {
        private readonly StringBuilder _urlBuilder;
        public UrlBuilder(string url)
        {
            _urlBuilder = new StringBuilder(url);
        }
        public UrlBuilder AddSegment(string segment)
        {
            _urlBuilder.Append("/");
            _urlBuilder.Append(segment);
            return this;
        }

        public UrlBuilder AddQuery(string name, string value)
        {
            if (_urlBuilder.ToString().Contains("?"))
            {
                _urlBuilder.Append("&");
            }
            else
            {
                _urlBuilder.Append("?");
            }

            _urlBuilder.Append($"{name}={value}");
            return this;
        }

        public string Build()
        {
            return _urlBuilder.ToString();
        }
    }
}
