using AuthAPI.Models;
using AuthAPI.Models.DTO;
using AuthAPI.Services.Interfaces;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace AuthAPI.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class UserController : ControllerBase
    {
        private readonly IUserService _userService;

        public UserController(IUserService userService)
        {
            _userService = userService;
        }

        /// <summary> Efetuar login </summary>
        /// <remarks>
        /// Exemplo de requisição:
        /// 
        ///     POST /signin
        ///     {
        ///        "email": "guilguimaraes2019@gmail.com",
        ///        "password": "admin123"
        ///     }
        ///     
        /// </remarks>
        /// <param name="loginDTO">Usuário (email) e Senha (password): </param>
        /// <returns>Token retornado</returns>
        /// <response code="200">OK - Usuário Autenticado</response>
        /// <response code="400">BadRequest - Requisição do Cliente é Inválida</response>
        [HttpPost("signin")]
        [ProducesResponseType(StatusCodes.Status200OK, Type = typeof(TokenDTO))]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        public IActionResult Signin([FromBody] LoginDTO loginDTO)
        {
            if (loginDTO == null) return BadRequest("Invalid client request");
            
            TokenDTO token = _userService.Authenticate(loginDTO);
            if (token == null) return BadRequest("Invalid client request");

            return Ok(token);
        }

        /// <summary> Obter um RefreshToken </summary>
        /// <remarks>
        /// Exemplo de requisição:
        /// 
        ///     POST /refresh
        ///     {
        ///        "accessToken": "11f9dsfddasdasd48d9ds8f1ds",
        ///        "refreshToken": "11f9dsfddasd9a41d"
        ///     }
        ///     
        /// </remarks>
        /// <param name="tokenDTO">Token de Acesso (accessToken) e RefreshToken (refreshToken): </param>
        /// <returns>Novo Token retornado</returns>
        /// <response code="200">OK - Novo Token Gerado</response>
        /// <response code="400">BadRequest - Requisição do Cliente é Inválida</response>
        [HttpPost("refresh")]
        [ProducesResponseType(StatusCodes.Status200OK, Type = typeof(TokenDTO))]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        public IActionResult Refresh([FromBody] TokenDTO tokenDTO)
        {   
            if (tokenDTO == null) return BadRequest("Invalid client request");

            TokenDTO token = _userService.RefreshToken(tokenDTO);
            if (token == null) return BadRequest("Invalid client request");

            return Ok(token);
        }

        /// <summary> Deslogar </summary>
        /// <response code="204">NoContent - Logout: RefreshToken Anulado</response>
        /// <response code="400">BadRequest - Requisição do Cliente é Inválida</response>
        /// <response code="401">Unauthorized - Usuário não Autorizado</response>
        [Authorize]
        [HttpGet("revoke")]
        [ProducesResponseType(StatusCodes.Status204NoContent)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status401Unauthorized)]
        public IActionResult Revoke()
        {   
            User user = (User)HttpContext.Items["User"];
            if(!_userService.RevokeToken(user)) return BadRequest("Invalid client request");
            return NoContent();
        }

        /// <summary> Verificar se está autenticado </summary>
        /// <returns>Message</returns>
        /// <response code="200">OK - Está Autenticado</response>
        /// <response code="401">Unauthorized - Usuário não Autorizado</response>
        [Authorize]
        [HttpGet("isauthenticated")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status401Unauthorized)]
        public IActionResult IsAuthenticated(){
            return Ok("Hello " + User.Identity.Name+", you are authenticated!");
        }

        /// <summary> Verificar se é um usuário admin </summary>
        /// <returns>Message</returns>
        /// <response code="200">OK - É Admin</response>
        /// <response code="401">Unauthorized - Usuário não Autorizado</response>
        /// <response code="403">Forbidden - Usuário não tem permissão no Endpoint</response>
        [Authorize(Roles = Roles.Admin)]
        [HttpGet("isadmin")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status401Unauthorized)]
        [ProducesResponseType(StatusCodes.Status403Forbidden)]
        public IActionResult IsAdmin(){
            return Ok("Hello " + User.Identity.Name+", you are admin!");
        }

        /// <summary> Verificar se é um usuário normal </summary>
        /// <returns>Message</returns>
        /// <response code="200">OK - É Normal</response>
        /// <response code="401">Unauthorized - Usuário não Autorizado</response>
        /// <response code="403">Forbidden - Usuário não tem permissão no Endpoint</response>
        [Authorize(Roles = Roles.Normal)]
        [HttpGet("isnormal")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status401Unauthorized)]
        [ProducesResponseType(StatusCodes.Status403Forbidden)]
        public IActionResult IsNormal(){
            return Ok("Hello " + User.Identity.Name+", you are normal user!");
        }
    }
}