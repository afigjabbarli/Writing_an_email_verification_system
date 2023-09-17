using System.ComponentModel.DataAnnotations.Schema;

namespace Pustok.Contracts
{
    public class CurrencyResult
    {
        public bool Success { get; set; }
        public long Timestamp { get; set; }
        public string Base { get; set; }
        public DateTime Date { get; set; }

        public Dictionary<string, decimal> Rates { get; set; }
    }

}
