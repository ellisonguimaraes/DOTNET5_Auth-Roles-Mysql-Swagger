using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using AuthAPI.Authorization.Interfaces;
using AuthAPI.Models;
using AuthAPI.Models.Configuration;
using AuthAPI.Models.DTO;
using Microsoft.IdentityModel.Tokens;

namespace AuthAPI.Authorization
{
    public class JwTUtils : IJwTUtils
    {
        private readonly TokenConfiguration _configuration;

        public JwTUtils(TokenConfiguration configuration)
        {
            _configuration = configuration;
        }

        public TokenDTO GenerateToken(User user)
        {
            // Gerando novos tokens
            string accessToken = GenerateAccessToken(user);
            string refreshToken = GenerateRefreshToken();

            // Gerando as datas de criação e expiração do Token de Acesso
            DateTime createDate = DateTime.Now;
            DateTime expirationDate = createDate.AddMinutes(_configuration.Minutes);

            // Retornando Token
            return new TokenDTO{
                Authenticated = true,
                CreatedDate = createDate.ToString("yyyy-MM-dd HH:mm:ss"),
                ExpirationDate = expirationDate.ToString("yyyy-MM-dd HH:mm:ss"),
                AccessToken = accessToken,
                RefreshToken = refreshToken
            };
        }

        public string GenerateAccessToken(User user)
        {
            // Pegando a Secret do appsettings.json
            SymmetricSecurityKey secretKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration.Secret));
            
            // Definindo signincredentials
            SigningCredentials signingCredentials = new SigningCredentials(secretKey, SecurityAlgorithms.HmacSha256);

            // Definindo as Claims
            List<Claim> claims = new List<Claim>{
                new Claim("id", user.Id.ToString()),
                new Claim(ClaimTypes.Name, user.Email),
                new Claim(ClaimTypes.Role, user.Role)
            };

            // Configurando a descrição do token
            var tokenDescriptor = new SecurityTokenDescriptor{
                Subject = new ClaimsIdentity(claims),
                Audience = _configuration.Audience,
                Issuer = _configuration.Issuer,
                Expires = DateTime.UtcNow.AddMinutes(_configuration.Minutes),
                SigningCredentials = signingCredentials
            };

            // Gerando token
            var tokenHandler = new JwtSecurityTokenHandler();
            var token = tokenHandler.CreateToken(tokenDescriptor);
            
            // Retornando o token em string
            return tokenHandler.WriteToken(token);
        }

        public string GenerateRefreshToken()
        {
            // Gerando Refresh Token
            var randomNumber = new byte[32];
            string refreshToken = null;
            using(var rng = RandomNumberGenerator.Create()){
                rng.GetBytes(randomNumber);
                refreshToken = Convert.ToBase64String(randomNumber);
            }
            return refreshToken;
        }
        
        public int? ValidateJwTToken(string token)
        {
            if (token == null) return null;
            
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.UTF8.GetBytes(_configuration.Secret);

            try
            {
                tokenHandler.ValidateToken(token, new TokenValidationParameters
                {
                    ValidateAudience = false,
                    ValidateIssuer = false,
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(key),
                    ValidateLifetime = false
                }, out SecurityToken validatedToken);
                
                var jwtToken = (JwtSecurityToken)validatedToken;
                var userId = int.Parse(jwtToken.Claims.First(x => x.Type == "id").Value);

                // Retorna o Id do User pelo JWT token se for validado com sucesso
                return userId;
            }
            catch
            {
                return null;
            }
        }
    }
}