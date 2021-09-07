namespace AuthAPI.Models.DTO
{
    public class TokenDTO
    {
        public bool Authenticated { get; set; }
        public string CreatedDate { get; set; }
        public string ExpirationDate { get; set; }
        public string AccessToken { get; set; }
        public string RefreshToken { get; set; }
    }
}