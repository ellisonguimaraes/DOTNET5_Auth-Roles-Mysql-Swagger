using System;
using System.Net.Mime;
using System.Collections.Generic;
using AuthAPI.Models;
using AuthAPI.Repository.Interfaces;
using AuthAPI.Models.Context;
using System.Linq;
using System.Text;
using System.Security.Cryptography;

namespace AuthAPI.Repository
{
    public class UserRepository : IUserRepository
    {
        private readonly ApplicationContext _context;

        public UserRepository(ApplicationContext context)
        {
            _context = context;
        }

        public List<User> GetAll() => _context.Users.ToList();

        public User GetById(long id) => _context.Users.SingleOrDefault(u => u.Id.Equals(id));

        public User GetByEmail(string email) => _context.Users.SingleOrDefault(u => u.Email.Equals(email));

        public User GetByRefreshToken(string refreshToken) => _context.Users.SingleOrDefault(u => u.RefreshToken.Equals(refreshToken));

        public User GetByLogin(string email, string password) {
            var passwordEncripted = new SHA256CryptoServiceProvider().ComputeHash(Encoding.UTF8.GetBytes(password));

            return _context.Users.SingleOrDefault(u => u.Email.Equals(email) && 
                                                        u.Password.Equals(BitConverter.ToString(passwordEncripted)));
        }

        public User Create(User user) {
            try {
                _context.Users.Add(user);
                _context.SaveChanges();

            } catch(Exception) {
                throw;
            }

            return user;
        }

        public User Update(User user)
        {
            if (!_context.Users.Any(u => u.Id.Equals(user.Id))) return null;

            User getUser = _context.Users.SingleOrDefault(u => u.Id.Equals(user.Id));

            if (getUser != null) {
                try {
                    _context.Entry(getUser).CurrentValues.SetValues(user);
                    _context.SaveChanges();

                } catch (Exception) {
                    throw;
                }
            }
            
            return user;
        }

        public bool Delete(long id)
        {
            User user = _context.Users.SingleOrDefault(u => u.Id.Equals(id));

            if (user != null) {
                try {
                    _context.Users.Remove(user);
                    _context.SaveChanges();
                    return true;
                    
                } catch (Exception) {
                    throw;
                }
            }

            return false;
        }
    }
}