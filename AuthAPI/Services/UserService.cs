using System;
using System.Text;
using System.Linq;
using AuthAPI.Authorization.Interfaces;
using AuthAPI.Models;
using AuthAPI.Models.Configuration;
using AuthAPI.Models.Context;
using AuthAPI.Models.DTO;
using AuthAPI.Services.Interfaces;
using System.Security.Cryptography;
using AuthAPI.Repository.Interfaces;
using Microsoft.AspNetCore.Authorization;

namespace AuthAPI.Services
{
    public class UserService : IUserService
    {
        private readonly IUserRepository _repository;
        private readonly IJwTUtils _jwTUtils;
        private readonly TokenConfiguration _tokenConfiguration;

        public UserService(IUserRepository repository, IJwTUtils jwTUtils, TokenConfiguration tokenConfiguration)
        {
            _repository = repository;
            _jwTUtils = jwTUtils;
            _tokenConfiguration = tokenConfiguration;
        }

        public TokenDTO Authenticate(LoginDTO loginDTO)
        {
            User user = _repository.GetByLogin(loginDTO.Email, loginDTO.Password);
            
            if (user == null) return null;

            // Obtendo novos Tokens com o Token de Acesso e o RefreshToken
            TokenDTO token = _jwTUtils.GenerateToken(user);

            // Atualizando User
            user.RefreshToken = token.RefreshToken;
            user.RefreshTokenExpiryTime = DateTime.Parse(token.ExpirationDate);
            _repository.Update(user);

            return token;
        }

        public TokenDTO RefreshToken(TokenDTO tokenDTO)
        {
            User user = _repository.GetByRefreshToken(tokenDTO.RefreshToken);

            // É verificado se user n é nulo ou se está expirado.
            if (user == null || user.RefreshTokenExpiryTime <= DateTime.Now)
                return null;

            // Gerando novos Tokens com o Token de Acesso e o RefreshToken
            TokenDTO token = _jwTUtils.GenerateToken(user);
            
            // Atualizando User
            user.RefreshToken = token.RefreshToken;
            user.RefreshTokenExpiryTime = DateTime.Parse(token.ExpirationDate);
            _repository.Update(user);

            return token;
        }

        public bool RevokeToken(User user)
        {
            // Configura RefreshToken de User como nulo e atualiza o banco
            user.RefreshToken = null;
            _repository.Update(user);

            return true;
        }
    }
}