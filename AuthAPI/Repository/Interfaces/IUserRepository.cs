using System.Collections.Generic;
using AuthAPI.Models;

namespace AuthAPI.Repository.Interfaces
{
    public interface IUserRepository
    {
        List<User> GetAll();
        User GetById(long id);
        User GetByEmail(string email);
        User GetByRefreshToken(string refreshToken);
        User GetByLogin(string email, string password);
        User Create(User user);
        User Update(User user);
        bool Delete(long id);
    }
}