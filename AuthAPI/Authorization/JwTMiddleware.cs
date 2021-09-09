using System.Linq;
using System.Threading.Tasks;
using AuthAPI.Authorization.Interfaces;
using AuthAPI.Repository.Interfaces;
using Microsoft.AspNetCore.Http;

namespace AuthAPI.Authorization
{
    public class JwTMiddleware
    {
        private readonly RequestDelegate _next;

        public JwTMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public async Task Invoke(HttpContext context, IUserRepository userRepository, IJwTUtils jwtUtils){
            // Obtém o Token no Header da Request (Ex: Bearer fdi324df2fvsd)
            var token = context.Request.Headers["Authorization"].FirstOrDefault()?.Split(" ").Last();

            // Valida o Token retornando o ID do usuário na tabela
            var userId = jwtUtils.ValidateJwTToken(token);

            if (userId != null)
                // Se o Id não for nulo, pegamos o User no banco.
                context.Items["User"] = userRepository.GetById(userId.Value);

            await _next(context);
        }
    }
}