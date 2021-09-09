using AuthAPI.Models;
using AuthAPI.Models.DTO;

namespace AuthAPI.Authorization.Interfaces
{
    public interface IJwTUtils
    {
        TokenDTO GenerateToken(User user);
        string GenerateAccessToken(User user);
        string GenerateRefreshToken();
        int? ValidateJwTToken(string token);
    }
}