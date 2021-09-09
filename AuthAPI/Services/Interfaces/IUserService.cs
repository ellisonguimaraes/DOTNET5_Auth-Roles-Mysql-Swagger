using AuthAPI.Models;
using AuthAPI.Models.DTO;

namespace AuthAPI.Services.Interfaces
{
    public interface IUserService
    {
        TokenDTO Authenticate(LoginDTO loginDTO);
        TokenDTO RefreshToken(TokenDTO tokenDTO);
        bool RevokeToken(User user);
    }
}