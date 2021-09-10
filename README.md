# Projeto Base sobre Autenticação e Autorização com .NET 5 WebAPI, envolvendo Swagger, Roles e Refresh Token

Criador por Ellison W. M. Guimarães. 

LinkedIn: [https://www.linkedin.com/in/ellisonguimaraes/](https://www.linkedin.com/in/ellisonguimaraes/)

E-mail: ellison.guimaraes@gmail.com



# ÍNDICE

[TOC]



# 1. Entendendo Swagger, Autenticação e Autorização com Roles e RefreshToken.

Para esse projeto utilizamos as seguintes tecnologias:

- O **Entity Framework** com MYSQL. A dependência a seguir é necessária:

    ```C#
    <PackageReference Include="Pomelo.EntityFrameworkCore.MySql" Version="5.0.1" />
    ```

- A documentação com **Swagger**. A dependência a seguir é necessária:

    ```C#
    <PackageReference Include="Swashbuckle.AspNetCore" Version="5.6.3" />
    ```

- O **JwTBearer** utilizado para a autenticação e autorização. A dependência a seguir é necessária:

    ```C#
    <PackageReference Include="Microsoft.AspNetCore.Authentication.JwTBearer" Version="5.0.9" />
    ```

Além disso, usamos um banco de dados `authdb2` onde a string de conexão é encontrada no `appsettings.json`:

```json
"ConnectionStrings": {
	"MySQLConnectionString": "Server=localhost;DataBase=authdb2;Uid=root;Pwd=admin"
},
```

E também a configuração no `Startup.cs`: na primeira linha pegamos a string de conexão do `appsettings.json` através do `Configuration`, e na linha seguinte, configuramos o uso do banco.

```C#
var connectionString = Configuration["ConnectionStrings:MySQLConnectionString"];
services.AddDbContext<ApplicationContext>(options =>  options.UseMySql(connectionString, 
                                                      ServerVersion.AutoDetect(connectionString))
                                         );
```

E para finalizar, precisamos criar o modelo aplicado ao banco de dados `User` e o `DbContext`. O modelo `User` já mapeado com as tag's `[Column]` e `[Table]` como mostra a seguir:

```C#
using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace AuthAPI.Models {
    [Table("users")]
    public class User {
        [Key]
        [Column("id")]
        public long Id { get; set; }

        [Column("email")]
        public string Email { get; set; }
        
        [Column("password")]
        public string Password { get; set; }

        [Column("role")]
        public string Role { get; set; }

        [Column("refresh_token")]
        public string RefreshToken { get; set; }
        
        [Column("refresh_token_expiry_time")]
        public DateTime RefreshTokenExpiryTime { get; set; }
    }
}
```

E também o `DbContext` (classe que faz o acesso ao banco através do Entity Framework):

```C#
using Microsoft.EntityFrameworkCore;

namespace AuthAPI.Models.Context {
    public class ApplicationContext : DbContext {
        
        public ApplicationContext() { }       

        public ApplicationContext(DbContextOptions<ApplicationContext> options) : base(options) { }

        public DbSet<User> Users { get; set; }
    }
}
```

> Como não se trata de uma abordagem *Code First*, precisamos criar o banco manualmente. O banco de nome `authdb2` segue o seguinte SQL:
>
> ```sql
> CREATE TABLE `users` (
> 	`id` INT(11) NOT NULL AUTO_INCREMENT,
> 	`email` VARCHAR(100) NOT NULL DEFAULT '0',
> 	`password` VARCHAR(130) NOT NULL DEFAULT '0',
> 	`role` VARCHAR(30) NOT NULL DEFAULT '0',
> 	`refresh_token` VARCHAR(500) NULL DEFAULT '0',
> 	`refresh_token_expiry_time` DATETIME NULL DEFAULT NULL,
> 	PRIMARY KEY (`id`),
> 	UNIQUE `email` (`email`)
> )
> ENGINE=InnoDB DEFAULT CHARSET=LATIN1;
> 
> INSERT INTO `users` (`email`, `password`, `role`, `refresh_token`, `refresh_token_expiry_time`) VALUES
> ('ellison.guimaraes@gmail.com', '24-0B-E5-18-FA-BD-27-24-DD-B6-F0-4E-EB-1D-A5-96-74-48-D7-E8-31-C0-8C-8F-A8-22-80-9F-74-C7-20-A9', 'admin', 'h9lzVOoLlBoTbcQrh/e16/aIj+4p6C67lLdDbBRMsjE=', '2020-09-27 17:30:49');
> 
> INSERT INTO `users` (`email`, `password`, `role`, `refresh_token`, `refresh_token_expiry_time`) VALUES 
> ('guilguimaraes2019@gmail.com', '24-0B-E5-18-FA-BD-27-24-DD-B6-F0-4E-EB-1D-A5-96-74-48-D7-E8-31-C0-8C-8F-A8-22-80-9F-74-C7-20-A9', 'normal', '', '2021-09-11 13:04:22');
> ```



## 1.1. Padrão Repository

Utilizamos neste projeto o padrão *Repository*, mas do que se trata? Um repositório é essencialmente uma coleção de objetos de domínio em memória, e, com base nisso o padrão *Repository* permite realizar o isolamento entre a camada de acesso a dados (**DAL**) de sua aplicação e sua camada de apresentação (**UI**) e camada de negócios (**BLL**).

Ao utilizar o padrão *Repository* você pode realizar a persistência e a separação de interesses em seu código de acesso a dados visto que ele encapsula a lógica necessária para persistir os objetos do seu domínio na sua fonte de armazenamento de dados.

Para acesso aos dados do contexto criamos a interface `IUserRepository.cs` e a sua implementação `UserRepository.cs` que seguem as seguintes implementações:

```C#
using System.Collections.Generic;
using AuthAPI.Models;

namespace AuthAPI.Repository.Interfaces {
    public interface IUserRepository {
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
```

E sua implementação:

```C#
using System;
using System.Collections.Generic;
using AuthAPI.Models;
using AuthAPI.Repository.Interfaces;
using AuthAPI.Models.Context;
using System.Linq;
using System.Text;
using System.Security.Cryptography;

namespace AuthAPI.Repository {
    
    public class UserRepository : IUserRepository {
        
        private readonly ApplicationContext _context;

        public UserRepository(ApplicationContext context) {
            _context = context;
        }

        public List<User> GetAll() => _context.Users.ToList();
        public User GetById(long id) => _context.Users.SingleOrDefault(u => u.Id.Equals(id));
        public User GetByEmail(string email) => _context.Users.SingleOrDefault(u =>
                                                                               u.Email.Equals(email));

        public User GetByRefreshToken(string refreshToken) => _context.Users.SingleOrDefault(u => 																	u.RefreshToken.Equals(refreshToken));

        public User GetByLogin(string email, string password) {
            var passwordEncripted = new SHA256CryptoServiceProvider()
                						.ComputeHash(Encoding.UTF8.GetBytes(password));

            return _context.Users.SingleOrDefault(u => u.Email.Equals(email) &&                                          						u.Password.Equals(BitConverter.ToString(passwordEncripted)));
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

        public User Update(User user) {
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

        public bool Delete(long id) {
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
```

Precisamos então configurar no método `ConfigureServices` da classe `Startup` a Injeção de Dependência (DI) para o repositório `UserRepository`:

```C#
services.AddScoped<IUserRepository, UserRepository>();
```



# 2. Swagger

O **Swagger** é um framework utilizado para automatizar a construção da documentação de uma Web API, e ele consegue descrever, consumir e visualizar a API. Sendo uma das ferramentas mais utilizadas para esta função, a empresa por trás dela (a *SmartBear Software*), decidiu criar o ***Open API Iniciative*** e renomearam as especificações do **Swagger** para ***OpenAPI Specification***.

Ela visa padronizar as API's REST, desta forma descreve os recursos que uma API deve possuir, como endpoints, dados recebidos, dados retornados, códigos HTTP, métodos de autenticação, entre outros.

> A implementação do **Swagger** para o **ASP.NET Web API** se chama **Swashbuckle** referenciada nas dependências no início deste Markdown.



## 2.1. Especificação do Swagger

O ponto mais importante do **Swagger** é a sua especificação, que era chamada de *Swagger specification* e agora é *OpenAPI Specification*. Esta especificação trata-se de um documento, `JSON` ou `YAML`, que define a estrutura da API. Indicando os endpoints, formatos de entrada, de saída, exemplos de requisições, forma de autenticação, etc.

Abaixo você pode ver a especificação definida em JSON do projeto aqui descrito:

<img src="README.assets/image-20210909135713848.png" alt="image-20210909135713848"  />

A documentação toda encontra-se no link: http://localhost:5000/swagger/v1/swagger.json. Esse link também é disponibilizado na UI, logo abaixo do título.



## 2.2. Configurações Necessárias

Ao instalar o pacote **Swagger** com ele vem incorporado o **Swagger-UI** que basicamente é uma interface que gera dinamicamente as documentação da sua **API** e um **Sandbox** no qual podemos fazer os testes e a chamadas na nossa **API** e tudo isso de forma automática.

Inicialmente precisamos configurar ele no `Startup.cs`. No método `ConfigureServices` temos a configuração básica a seguir:

```C#
services.AddSwaggerGen(c =>
            {
                c.SwaggerDoc("v1", new OpenApiInfo { 
                    Title = "Authentication and Authorization .NET5 (Base)", 
                    Version = "v1",
                    Description = "Base project for authentication and authorization with Roles, 																UserManager, RefreshToken and Revoke",
                    Contact = new OpenApiContact {
                        Name = "Ellison Guimarães",
                        Email = "ellison.guimaraes@gmail.com",
                        Url = new Uri("https://github.com/ellisonguimaraes")
                    }
                });
            });
```

- O `services.AddSwaggerGen` recebe uma configuração `c.SwaggerDoc`, onde seu primeiro parâmetro é a versão da API e o segundo parâmetro um objeto do tipo `OpenApiInfo`;
- O objeto `OpenApiInfo` define informações básicas da documentação, como:
    - `Title` sendo o título dado a API;
    - `Version` sendo a versão atual da API;
    - `Description` a descrição superior da API;
    - `Contact` que recebe um objeto do tipo `OpenApiContact`, com atributos do autor:
        - `Name` com o nome do autor;
        - `Email` sendo o e-mail do autor;
        - `Url` que recebe um objeto do tipo `Uri` indicando um link para contato.

Após a configuração no método `ConfigureServices`, ainda precisamos adicionar ao método `Configure` algumas informações:

```C#
app.UseSwagger();

app.UseSwaggerUI(c => {
    c.RoutePrefix = string.Empty;
    c.SwaggerEndpoint("/swagger/v1/swagger.json", "Authentication and Authorization .NET5 (Base)");
});
```

- O `app.UseSwagger()` é responsável por gerar o JSON da especificação;
- O `app.UseSwaggerUI()` é responsável por gerar a interface (página HTML) de documentação:
    - Ela recebe uma configuração do tipo `c.SwaggerEndpoint()` onde seu primeiro parâmetro é o ENDPOINT do `swagger.json` (a especificação), e o segundo o titulo novamente;
    - Recebe também uma configuração do tipo `c.RoutePrefix` que indica a rota usada para apresentação da interface UI. Nesse caso está setado como `string.Empty` e faz com que a UI seja exibida na rota raiz, ou seja, `http://localhost:5000/`.

> **OBSERVAÇÃO IMPORTANTE!**
>
> As configurações do **Swagger** devem ficar entre o `UseRouting` e o `UseEndPoint`.



Após essa configuração base, já podemos visualizar a interface Swagger UI:

![image-20210909140247878](README.assets/image-20210909140247878.png)

![image-20210909140306445](README.assets/image-20210909140306445.png)

Podemos observar as configurações feitas:

- A configuração do título e a versão da API é identificada na parte superior;
- Link para o JSON da especificação e Descrição abaixo do título;
- Observe que o autor da API foi colocado com um link de acesso;
- A configuração de e-mail gerou um link para que o usuário clique e possa enviar um email;

Ao expandir um dos verbos podemos obter informações sobre ele:

![image-20210909140824048](README.assets/image-20210909140824048.png)

![image-20210909140848989](README.assets/image-20210909140848989.png)



Informações sobre a rota são demostrados:

- Na parte superior ao lado da rota é possível identificar a descrição da rota;
- Logo abaixo podemos colocar alguma informação extra, que nesse caso foi colocado o corpo da requisições necessária em JSON;
- Se tiver parâmetros são demostrados na guia *Parameters*;
- O corpo da requisição com uma descrição;
- Os possíveis códigos de *response* e a descrição do que significa em cada uma delas;

Todas essas configurações de rota são feitas no *Controller* através de ==Tag's== e ==*XML Comments*==. Para o uso de *XML Comments* é necessário uma configuração específica para isso, que também está presente neste projeto.

Além disso, é possível observar alguns itens de autenticação na Swagger UI. Para que o Swagger possa dar suporte a ==Autenticação e Autorização==, também são necessárias algumas configurações.



### 2.2.1. Configurando para suportar XML Comments

Alguns configurações foram feitas no método `ConfigureServices` do `Startup.cs` para suporte ao **Swagger**, porém, para que haja suporte para *XML Comments* é necessário aplicar mais uma configuração no `AddSwaggerGen`:

```C#
services.AddSwaggerGen(c =>
            {
                c.SwaggerDoc("v1", new OpenApiInfo { 
                    Title = "Authentication and Authorization .NET5 (Base)", 
                    Version = "v1",
                    Description = "Base project for authentication and authorization with Roles, 																UserManager, RefreshToken and Revoke",
                    Contact = new OpenApiContact {
                        Name = "Ellison Guimarães",
                        Email = "ellison.guimaraes@gmail.com",
                        Url = new Uri("https://github.com/ellisonguimaraes")
                    }
                });
                
                // Configure XML Comments to Swagger
                var xmlFile = $"{Assembly.GetExecutingAssembly().GetName().Name}.xml";
                var xmlPath = Path.Combine(AppContext.BaseDirectory, xmlFile);
                c.IncludeXmlComments(xmlPath);
            });



```

A operação `c.IncludeXmlComments` possibilita que o **Swagger** utilize o **XML** de documentação da aplicação, exibindo assim textos que descrevem as diferentes opções disponíveis e seus parâmetros esperados. Iremos abordar o *XML Comments* no tópico **Customizando a Documentação**.

Além dessa configuração, é necessário inserir no arquivo `.csproj` as linhas a seguir:

```xml
<Project Sdk="Microsoft.NET.Sdk.Web">
	<PropertyGroup>
		<TargetFramework>net5.0</TargetFramework>
	</PropertyGroup>

	<ItemGroup>
		<PackageReference Include="Microsoft.AspNetCore.Authentication.JwTBearer" Version="5.0.9" />
		<PackageReference Include="Pomelo.EntityFrameworkCore.MySql" Version="5.0.1" />
		<PackageReference Include="Swashbuckle.AspNetCore" Version="5.6.3" />
	</ItemGroup>
    
	<!-- SWAGGER XML COMMENTS -->
	<PropertyGroup>
		<GenerateDocumentationFile>true</GenerateDocumentationFile>
		<NoWarn>$(NoWarn);1591</NoWarn>
	</PropertyGroup>
	<!-------------------------->
</Project>

```

Essas linhas fazem com que um arquivo de documentação XML seja gerado e utilizado pelo **Swagger**.



### 2.2.2. Configurando para suportar Autenticação e Autorização

Para que o **Swagger** suporte Autenticação e Autorização, é necessário ainda mais uma configuração no método `ConfigureServices` do `Startup.cs`

```C#
// Configure Authentication Support in Swagger Page
c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme {
    Description = @"JWT Authorization header using the Bearer scheme. 
                                Enter 'Bearer' [space] and then your token in the text input below.
                                Example: 'Bearer 12345abcdef'",
    Name = "Authorization",
    In = ParameterLocation.Header,
    Type = SecuritySchemeType.ApiKey,
    Scheme = "Bearer"
});

c.AddSecurityRequirement(new OpenApiSecurityRequirement() {
    {
        new OpenApiSecurityScheme {
            Reference = new OpenApiReference
            {
                Type = ReferenceType.SecurityScheme,
                Id = "Bearer"
            },
            Scheme = "oauth2",
            Name = "Bearer",
            In = ParameterLocation.Header,
        },
        new List<string>()
    }
});
```

Podemos ver algumas configurações feitas do `c.AddSecurityDefinition` na **Swagger UI** ao clicar no cadeado *Authorize*:

![image-20210909151459981](README.assets/image-20210909151459981.png)

A partir destas configurações o *Swagger* e *Swagger UI* terá suporte a autenticação, disponibilizando campos para inserção do Token JwT por exemplo.

> Lembrando que para autorizar o Key enviada precede do nome `Bearer [Key]`, ou seja:
>
> ```json
> Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjEiLCJ1bmlxdWVfbmFtZSI6ImVsbGlzb24uZ3VpbWFyYWVzQGdtYWlsLmNvbSIsInJvbGUiOiJhZG1pbiIsIm5iZiI6MTYzMTIxMTI0NCwiZXhwIjoxNjMxMjE0ODQ0LCJpYXQiOjE2MzEyMTEyNDQsImlzcyI6Iklzc3VlckF1dGgiLCJhdWQiOiJBdWRpZW5jZUF1dGgifQ.RcIGBhSFN6ZLUflbhVEgFZ2F-U3NoxWGj_2G8gbKr_8
> ```



## 2.3. Customizando a Documentação

Para exemplificar a customização, iremos pegar a rota de `Signin` no `UserController.cs`:

```C#
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
```

![image-20210909153316994](README.assets/image-20210909153316994.png)

<img src="README.assets/image-20210909154228620.png" alt="image-20210909154228620" style="zoom:50%;" />

A seguir iremos falar sobre cada uma das Tag's do *XML Comments*:

- O `<summary>` representa a parte em verde da imagem. É a representação do que faz a rota;
- O `<remarks>` representa a parte em vermelho da imagem, e é usado para descrever principalmente um exemplo da requisição;
- O `<param>` representa a parte em amarelo da imagem. E se trata da descrição do objeto recebido por parâmetro no método. É necessário o atributo `name` recebendo o mesmo nome do atributo no parâmetro;
- O `<returns>` o retorno do método;
- É suportado múltiplos `<response>` e são os possíveis códigos de resposta do método. Cada um `<response>` recebe um parâmetro `code` e é informado a descrição que aparece em azul nas imagens acima.

Além das Tag's do *XML Comments*, também temos as tag's `[ProducesResponseType]` que são utilizadas diretamente no *controller*. Podemos utilizar ela de duas formas:

- Informando o **code** de retorno: `[ProducesResponseType(StatusCodes.Status400BadRequest)]` informando entre parênteses o código a partir de um objeto estático `StatusCodes` (mais recomendada); ou informar diretamente o código em inteiro como a seguir: `[ProducesResponseType(200)]`;
- Informando o **code** de retorno e o objeto retornado: `[ProducesResponseType(StatusCodes.Status200OK, Type = typeof(TokenDTO))]`.



# 3. Autenticação e Autorização

A partir deste momento vamos implementar autenticação e autorização com **Refresh Tokens**. Quando se trata desses assuntos podemos identificar alguns termos:

- A **autenticação** diz quem você é. Ela é responsável por identificar o usuário ou quem estiver acessando a API;
- A **autorização** por sua vez, diz o que o usuário pode fazer.

A autorização se dá por meio de **Roles**, **Claims** e **Policies**, que restringem ou permitem o acesso do usuário a determinada parte da aplicação.

- Um **Role (perfil)** é um papel, uma função, um cargo, algo que define acesso a um ou um grupo de usuários em partes da aplicação. 

    Normalmente trabalhamos com Roles em cenários mais simples, onde não necessitamos de muita interação, onde por exemplo, apenas sabendo que o usuário possui o papel de Gerente, já podemos tomar alguma decisão.

- Já um **Claim (afirmação)** é algo mais imperativo em que na maioria dos casos utilizamos para realizar alguma interação antes de deixar o usuário prosseguir.

    Por exemplo, se precisamos validar se o usuário pertence a uma empresa específica, se ele realizou determinada venda ou qualquer outra validação que dependa de banco de dados por exemplo, este é um cenário interessante para os **Claims**.

- E os **Policies (políticas)** nada mais são que as aplicações de **Roles** e **Claims** para determinar contratos de acessos a determinadas áreas de uma aplicação.

    Você pode ter vários **Roles** e **Claims** compondo uma política que determina acesso a uma parte do seu sistema.

Algumas outras definições são necessárias, como:

- O **Token** é uma chave encriptada, contendo informações do usuário, que só pode ser desencriptada com outra chave privada que fica no servidor, mais especificamente no `AppSettings.json`;

    Pode parecer estranho dizer que temos informações do usuário (Não sensíveis) em uma chave, mas ela garante que não precisamos armazenar estes **tokens**, tornando possível o que chamamos de *Stateless Applications*, ou aplicações sem estado.

    Isto é fundamental para o escalonamento de qualquer aplicação. Afinal, sempre que uma máquina nova da sua aplicação sobe, sua memória não é copiada.

- **JWT** é uma sigla que significa *Json Web Token* e nada mais é que o armazenamento das informações do token no formato JSON;



## 3.1. Funcionamento

O funcionamento do processo de autenticação é da seguinte forma:

- O processo de autenticação inicia-se em uma aplicação (Normalmente *frontend*) fazendo uma requisição para sua API;
- Nesta requisição serão enviados o usuário e senha (via BODY). Neste momento, nem preciso dizer que suas aplicações PRECISAM trafegar sobre HTTPS, isto é uma exigência do Google para indexar seu site;
- Com o usuário e senha, é feito o processo normal de verificação do *login*, e caso tudo ocorra bem, sua API utiliza uma chave PRIVADA (chave contida no `AppSettings.json`), que só ela tem para gerar um TOKEN contendo as informações que você desejar, no formato JWT.
- Neste momento, você tem uma chave enorme, com todas as informações que colocou previamente (Nunca armazene informações sensíveis nos **tokens**), encriptada com uma chave privada que só a API e no formato JSON.

Abaixo um exemplo de chave (do projeto) e sua decodificação:

![image-20210909193416955](README.assets/image-20210909193416955.png)

Essa chave decodificada tem o seguinte conteúdo: 

- O **HEADER** informa o tipo de criptografia e o tipo do token, que é JWT;
- O **PAYLOAD** contém três variáveis que foram inseridas nas *Claims* presente na classe `JwTUtils.cs`, são elas: `id`, `unique_name` e `role`. As duas ultimas `iss` e `aud` são variáveis configuradas no `appsettings.json`. Além delas as outras são particulares do Token.

Conforme comentei anteriormente, nós não ficamos "logados" na API, então após o *Login*, este **token** é retornado e deve ser enviado novamente a cada requisição.

> O site responsável por decodificar e visualizar melhor como é construído o Token é o [JSON Web Tokens - jwt.io](https://jwt.io/).



## 3.2. O que é Refresh Token?

==*E por que implementaríamos* ***Refresh Tokens***?== O fato de um **token** possuir um tempo de validade pré-determinado pode ser uma limitação em algumas situações. Expirado tal **token** um novo deverá ser gerado, a fim de permitir que se continue a interação com os recursos providos por uma API.

A solução para contornar esse problema envolvem o uso de **Refresh Tokens**:

- Um valor adicional (um segundo **token**) será gerado, a fim de permitir a solicitação posterior de um novo **token** de acesso atualizado;
- Este procedimento dispensa a necessidade de se repetir todo o processo de autenticação que aconteceu durante a obtenção do **token** inicial, contribuindo assim para uma maior performance.



## 3.4. A Implementação

### 3.4.1. Configurações do Token

Para gerar o Token algumas configurações são necessárias. Essas configurações normalmente se encontram no arquivo `appsettings.json`, e no caso desse projeto, tem chave de nome `TokenConfigurations`:

```C#
"TokenConfigurations": {
	"Audience": "AudienceAuth",
    "Issuer": "IssuerAuth",
    "Secret": "MY_SUPER_SECRET_KEY",
    "Minutes": 60,
    "DaysToExpiry": 7
},
```

Dos cinco atributos, iremos descrever os principais:

- A `Secret` é a o segredo usado pelo JwT para gerar o **Token**;
- O `Minutes` é quantos minutos durará o Token de Acesso;
- E o `DaysToExpiry` é a quantidade de dias para expirar o `RefreshToken`.

A classe `TokenConfiguration` é um modelo que receberá essas informações e será injetado via Injeção de Dependências (DI). A seguir veremos o `TokenConfiguration`:

```C#
namespace AuthAPI.Models.Configuration
{
    public class TokenConfiguration
    {
        public string Audience {get; set;}
        public string Issuer {get; set;}
        public string Secret {get; set;}
        public int Minutes {get; set;}
        public int DaysToExpiry {get; set;}
    }
}
```

 Agora precisamos injetar essa dependência no `Startup.cs` no método `ConfigureServices`:

```C#
// CREATE OBJECT
TokenConfiguration configuration = new TokenConfiguration();  

// GET TO appsettings.json => INSERTO TO TokenConfiguration configuration
new ConfigureFromConfigurationOptions<TokenConfiguration>(      
    Configuration.GetSection("TokenConfigurations")
).Configure(configuration);

// INJECTING DEPENDENCY
services.AddSingleton(configuration);
```

A partir desse momento o `TokenConfiguration` estará disponível em todo o programa via injeção de dependência e estará pronto para usarmos na geração do Token.



### 3.4.2. Gerando o Token

Para gerar o Token criamos a interface `IJwTUtils.cs` e sua implementação `JwTUtils.cs`. A interface é composta por:

```C#
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
```

- O método `string GenerateAccessToken(User user)` que recebe um `User` e retorna uma string contendo o Token de Acesso;

- O método `string GenerateRefreshToken()` que gera um novo **RefreshToken** válido;

- O método `TokenDTO GenerateToken(User user)` que faz o acesso aos dois últimos métodos e retorna um objeto do tipo `TokenDTO` que contém as seguintes informações:

    ```C#
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
    ```

    - `Authenticated` retorna uma afirmação `true` de que está autenticado;
    - `Created` retorna a data de geração do **Token**;
    - `Expiration` retorna a data de expiração do **Token**. Observe que é a data de geração (`Created`) mais os 60 minutos inseridos do `appsettings.json`;
    - O **Token de Acesso** `AccessToken` gerado pelo método `GenerateAccessToken`;
    - E o **Token de Atualização** `RefreshToken` gerado pelo método `GenerateRefreshToken`.

- Além desses método tem o `int? ValidateJwTToken(string token)` que recebe um Token, decodifica e retorna o `Id` do `User` presente no Token.



Já a classe `JwTUtils` implementa a interface `IJwTUtils` e recebe em seu construtor a injeção de dependência do `TokenConfiguration` para configurar o Token no momento de gerar. Veja a seguir:

```C#
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

namespace AuthAPI.Authorization {
    public class JwTUtils : IJwTUtils {
        private readonly TokenConfiguration _configuration;

        public JwTUtils(TokenConfiguration configuration) {
            _configuration = configuration;
        }

        public TokenDTO GenerateToken(User user) {
            // Gerando novos tokens
            string accessToken = GenerateAccessToken(user);
            string refreshToken = GenerateRefreshToken();

            // Gerando as datas de criação e expiração do Token de Acesso
            DateTime createDate = DateTime.Now;
            DateTime expirationDate = createDate.AddMinutes(_configuration.Minutes);

            // Retornando Token
            return new TokenDTO {
                Authenticated = true,
                CreatedDate = createDate.ToString("yyyy-MM-dd HH:mm:ss"),
                ExpirationDate = expirationDate.ToString("yyyy-MM-dd HH:mm:ss"),
                AccessToken = accessToken,
                RefreshToken = refreshToken
            };
        }

        public string GenerateAccessToken(User user) {
            // Pegando a Secret do appsettings.json
            SymmetricSecurityKey secretKey = new
                				SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration.Secret));
            
            // Definindo signincredentials
            SigningCredentials signingCredentials = new SigningCredentials(secretKey,
                                                                      SecurityAlgorithms.HmacSha256);

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
            using(var rng = RandomNumberGenerator.Create()) {
                rng.GetBytes(randomNumber);
                refreshToken = Convert.ToBase64String(randomNumber);
            }
            return refreshToken;
        }
        
        public int? ValidateJwTToken(string token) {
            if (token == null) return null;
            
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.UTF8.GetBytes(_configuration.Secret);

            try {
                tokenHandler.ValidateToken(token, new TokenValidationParameters {
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
                
            } catch {
                return null;
            }
        }
    }
```

E falaremos um pouco sobre cada método a seguir.



#### 3.4.2.1. O Método ValidateJwTToken

Esse método decodifica o Token com base na **SecretKey**, obtendo as *Claims* e os valores presentes nela (assim como é feito no site [JSON Web Tokens - jwt.io](https://jwt.io/)). Como nesse caso uma das *claims* é o `id`, é retornado ele na validação.

- Inicialmente ela recebe uma string contendo o Token de Acesso. Nesse Token, comentamos no tópico de **Funcionamento** do Token (tópico 3.1) que no **PAYLOAD** do token contém as *Claims*, que nesse código, são elas:

    - O `Id` do usuário;
    - O nome único (`unique_name`) no qual atribuímos o `user.Email`;
    - A **Role** do usuário.

    ```C#
    List<Claim> claims = new List<Claim> {
        new Claim("id", user.Id.ToString()),
        new Claim(ClaimTypes.Name, user.Email),
        new Claim(ClaimTypes.Role, user.Role)
    };
    ```

- Na linha 89 criamos um `JwTSecurityTokenHandler`, onde validamos na linha 93 enviando nossa **SecretKey** informada no `appsettings.json`, gerando um objeto do tipo `SecurityToken validatedToken`;

- Na linha 102 percorremos as *Claims* através de LINQ(`jwtToken.Claims.First(x => x.Type == "id").Value`) procurando o `id` e pegando o valor correspondente para retornamos;



#### 3.4.2.2. O Método GenerateAccessToken

O método `GenerateAccessToken` recebe um `User` e as configurações de geração de token `TokenConfiguration` via injeção de dependência (DI), gera um Token de Acesso com base no usuário, nas configurações de token e nas *Claims* definidas.

- Primeiramente ele receber um usuário `User`. Esses dados serão necessários para gerar a lista de *Claims* presente na linha 51; 

- São definidas duas variáveis no começo:

    - Uma `SymmetricSecurityKey secretKey` que recebe a **SecretKey** do `TokenConfiguration`;
    - E a `SigningCredentials signingCredentials` que recebe o objeto anterior `secretKey` e qual o algoritmo de criptografia, que nesse caso, é o `SecurityAlgorithms.HmacSha256`.

- Logo após, na linha 58, é criado um objeto do tipo `SecurityTokenDescriptor tokenDescriptor` que se trata da descrição do Token. Essa descrição contém todas as informações anteriormente definidas:

    - O `Subject` que é a lista de *Claims*;
    - `Audience` e `Issuer` advindas do `TokenConfiguration`;
    - O `Expires` que é o tempo de expiração do Token de Acesso, que é o momento atual mais a quantidade em minutos definida no `TokenConfiguration`;
    - O `SigningCredentials` definido anteriormente.

- Finalmente criamos um objeto do tipo `JwtSecurityTokenHandler`(linha 67), o qual criamos o `token` com base na descrição `tokenDescriptor`(linha 68);

- No retorno usamos o mesmo objeto do tipo `JwtSecurityTokenHandler` (da linha 67) para retornar o `token` em formato de string através do método `WriteToken`.

    

#### 3.4.2.3. O Método GenerateRefreshToken

Esse método não há muito segredo, ele gera uma *hash* (32 bytes) de forma randômica e retorna em formato de string para o método que o chamou. 



#### 3.4.2.4. O Método GenerateToken

Esse é o método que iremos chamar quando será necessário criar um Token no formato `TokenDTO`. Esse método:

- Utiliza do método `GenerateAccessToken`, informando o usuário `User`, para gerar um novo Token de Acesso (linha 24);
- Também o `GenerateRefreshToken` para gerar uma nova *hash* para **RefreshToken** (linha 25);
- Na linha 28 atribui o `DateTime.Now` para a variável `createDate` referente ao momento de criação do Token;
- Na linha 29 cria-se a data de expiração do Token com base no `createDate`, acrescentando a quantidade de minutos informados no `TokenConfiguration`.

Finalmente é retornado um `TokenDTO` com todas as informações geradas acima.



#### 3.4.2.5. Configurando a Injeção de Dependência

Finalmente é necessário inserir a interface e sua implementação à injeção de dependência no método `ConfigureServices` do `Startup.cs` para ficar disponível em todo o programa:

```C#
services.AddScoped<IJwTUtils, JwTUtils>();
```



### 3.4.3 Middleware

Nesse projeto foi criado um Middleware chamado `JwTMiddleware`. Veja a seguir a implementação do Middleware:

```C#
using System.Linq;
using System.Threading.Tasks;
using AuthAPI.Authorization.Interfaces;
using AuthAPI.Repository.Interfaces;
using Microsoft.AspNetCore.Http;

namespace AuthAPI.Authorization {
    public class JwTMiddleware {
        
        private readonly RequestDelegate _next;

        public JwTMiddleware(RequestDelegate next) {
            _next = next;
        }

        public async Task Invoke(HttpContext context, 
                                 IUserRepository userRepository, 
                                 IJwTUtils jwtUtils)
        {
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
```

Esse middleware intercepta a requisição:

- Primeiramente ele obtém o valor da **Key Authorization** presente no HEADER da requisição. Esse valor é o Token que informamos, no formato: `Bearer f58ds5f48ds6d`. O `Split(" ").Last()` faz retornar somente a última string de uma lista divida por espaço, que nesse caso, é exatamente uma string contendo somente o Token (sem a palavra ==Bearer==);
- Na linha 24, envia esse token ao método `ValidateJwTToken` do `JwTUtils` para descriptografar o Token e retornar o valor do *Claim* `id`;
- Se retornar algum valor, atribuímos ao `context.Items["User"]` o `User` que contém esse `id`.

Essa última atribuição permite que façamos o acesso do usuário mais facilmente através do `HttpContext.Items["User"]` do `ControllerBase`. Isso permite que em todos os `Controllers` que derivam de `ControllerBase` acessem o usuário.

> Não podemos esquecer de configurar o Middleware no método `Configure` presente no `Startup.cs`:
>
> ```C#
> // USE MIDDLEWARE JwTMiddleware
> app.UseMiddleware<JwTMiddleware>();
> ```



### 3.4.4. Implementando o Serviço (Camada de Negócio)

A camada de negócio contém o serviço `IUserService` e sua implementação `UserService`. Esse serviço recebe chamadas do *controller* para autenticação (com login e senha), gerar um novo Token com base no **RefreshToken** ou fazer *logout* com `RevokeToken`. 

A interface `IUserService` contém as seguintes assinaturas:

```C#
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
```

- O método `TokenDTO Authenticate(LoginDTO loginDTO)` recebe um objeto do tipo `LoginDTO` com informações de login e senha e retorna um `TokenDTO` com os novos tokens (**AccessToken** e **RefreshToken**);

    A classe `LoginDTO` tem a seguinte sintaxe:

    ```C#
    namespace AuthAPI.Models.DTO
    {
        public class LoginDTO
        {
            public string Email { get; set; }
            public string Password { get; set; }
        }
    }
    ```

- O método `TokenDTO RefreshToken(TokenDTO tokenDTO)` recebe os um objeto do tipo `TokenDTO` com os tokens antigos (**AccessToken** e **RefreshToken**) e retorna tokens novos `TokenDTO` se o **RefreshToken** for válido e se não estiver expirado;

- O método `bool RevokeToken(User user)` recebe um usuário e faz o *logout*. Obs: o *logout* nesse momento é excluir o **RefreshToken** do banco de dados, isso faz com que ao usuário tentar usar o **RefreshToken** para gerar um novo Token ele não o consiga.

E finalmente a implementação do `IUserService`, o `UserService`:

```C#
using System;
using AuthAPI.Authorization.Interfaces;
using AuthAPI.Models;
using AuthAPI.Models.DTO;
using AuthAPI.Services.Interfaces;
using AuthAPI.Repository.Interfaces;

namespace AuthAPI.Services {
    public class UserService : IUserService {
        
        private readonly IUserRepository _repository;
        private readonly IJwTUtils _jwTUtils;

        public UserService(IUserRepository repository, IJwTUtils jwTUtils)
        {
            _repository = repository;
            _jwTUtils = jwTUtils;
        }

        public TokenDTO Authenticate(LoginDTO loginDTO) {
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

        public TokenDTO RefreshToken(TokenDTO tokenDTO) {
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

        public bool RevokeToken(User user) {
            // Configura RefreshToken de User como nulo e atualiza o banco
            user.RefreshToken = null;
            _repository.Update(user);

            return true;
        }
    }
}
```

A implementação `UserService` recebe via Injeção de Dependência a classe de repositório de `User`, o `UserRepository` e a classe `JwTUtils` que utilizamos para gerar e validar um token. Também contém os métodos da assinatura de `IUserService`:

- O método `Authenticate` recebe um objeto do tipo `LoginDTO` contendo login e senha. 

    - Na primeira linha do método é feita uma busca de usuário através do login e senha;

        > **OBSERVAÇÃO**:
        >
        > A senha presente no `loginDTO` não está criptografada. A criptografia da senha fica dentro do método `GetByLogin` do repositório de `User`.

    - Após tentar realizar uma busca, é verificado se o `User` recebido é nulo, se for é porque o usuário não foi encontrado ou a senha não corresponde, retornando `null` ao *controller*;

    - Se não for nulo, geramos um novo `TokenDTO` contendo novos tokens (**AccessToken** e **RefreshToken**) para o usuário;

    - Logo após a geração do token, na linha 29, precisamos atualizar o `User` com os novos **RefreshToken** e data de expiração do mesmo. Após atualizar `User` é necessário atualizar no banco com `_repository.Update(user)`;

    - Finalmente é retornado o token.

- O método `RefreshToken` recebe um objeto do tipo `TokenDTO` contendo o Token de Acesso antigo e o **RefreshToken**.

    - Na primeira linha é feita uma busca no repositório o usuário que tenha o **RefreshToken** informado;
    - Se o `User` for nulo ==ou== a data de expiração do token já se esgotou, é retornado um nulo ao *controller*; 
    - Se o `User` não for nulo e se a data de expiração ainda é válida, é gerado um novo token e atualizado em `User` e repositório (banco de dados) assim como no método `Authenticate`.

- O método `RevokeToken` recebe um `User` e limpa o `RefreshToken` dele com `null`. Após isso é atualizado no banco de dados com `_repository.Update(user)` e retorna `true` para o *controller*.



Para finalizar, é necessário configurar os serviços no `Startup` para Injeção de Dependência no programa. Será inserido no método `ConfigureService`:

```C#
services.AddScoped<IUserService, UserService>();
```



## 3.5. Configurações de Autenticação e Autorização no Startup

Até o presente momento já fizemos algumas configurações:

- No tópico 1: Fizemos a configuração do *Entity Framework*, pegando a string de conexão do `appsettings.json`;
- No tópico 1.1: fizemos a configuração de Injeção de Dependência (DI) do `UserRepository`;
- No tópico 2.2 foram feitas as configurações do Swagger nos métodos `ConfigureServices` e `Configure`. Além disso, também foram adicionadas configurações ao `csproj` para gerar o arquivo de documentação;
- No tópico 3.4.1 fizemos a configuração de acesso ao `appsettings.json` para acessar as configurações do token, atribuímos essas configurações a um objeto do tipo `TokenConfiguration` e disponibilizamos via DI;
- No tópico 3.4.2.5 fizemos a configuração de Injeção de Dependência (DI) do `IJwTUtils`;
- No tópico 3.4.3 fizemos a configuração do Middleware  `JwTMiddleware` no método `Configure`;
- No tópico 3.4.4 fizemos a configuração de Injeção de Dependência (DI) do Serviço `UserService`;



Algumas outras configurações importantes de autenticação e autorização:

- Devemos configurar no método `ConfigureServices` da classe `Startup` a configuração de `Authentication`:

    ```C#
    services.AddAuthentication(option => {
        option.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
        option.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    }).AddJwtBearer(option => {
        option.TokenValidationParameters = new TokenValidationParameters{
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = configuration.Issuer,
            ValidAudience = configuration.Audience,
            IssuerSigningKey = new
                SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration.Secret))
        };
    });
    ```

    > Observe que algumas informações do `TokenConfiguration configuration` são informadas nas configurações de autenticação. Além disso, o `IssuerSigningKey` já recebe a `SecretKey` com `SymmetricSecurityKey`.

- E também, devemos configurar no método `Configure` da classe `Startup` os middlewares responsáveis por autenticação e autorização:

    ```C#
    // USE AUTHENTICATION
    app.UseAuthentication();
    
    // USE AUTHORIZATION
    app.UseAuthorization();
    ```

A assim, finalizamos as implementações e configurações do que diz respeito a autenticação e autorização. Nesse momento, precisamos criar o *controller* responsável por fazer essas requisições.



## 3.6. Implementando o UserController

O controlador de `User` recebe em seus construtor a injeção de dependência `UserService` somente. O `UserController` contém as seguintes rotas:

- POST: `Signin` que recebe um `LoginDTO` via BODY Params e retorna um `TokenDTO`. Esse `LoginDTO` é passado para o `UserService.Authenticate(loginDTO)` para fazer a autenticação;
- POST: `Refresh` que recebe um `TokenDTO` e retorna outro atualizado. O `TokenDTO` recebido é enviado ao método `UserService.RefreshToken(tokenDTO)` que retorna um novo `TokenDTO` se o **RefreshToken** for válido;
- GET: `Revoke` que é utilizado para *logout*. Para acessar essa rota é necessário estar autenticado (tag `[Authorize]`), onde automaticamente o `User` é reconhecido pelo Middleware e atribuído ao `HttpContext.Items["User"]`, o qual, o método `Revoke` faz acesso enviando o `User` para o método `UserService.RevokeToken(user)`;
- GET: `IsAuthenticated` que contém a tag `[Authorize]` também, é usado para verificar se está autenticado, se sim, retorna uma mensagem ao BODY da resposta;
- GET: `IsAdmin` que contém a tag `[Authorize(Roles = Roles.Admin)]`, ou seja, só quem tem a *Claim* `Role` igual a ==admin== terá acesso a rota;
- GET: `IsNormal` que contém a tag `[Authorize(Roles = Roles.Normal)]`, ou seja, só quem tem a *Claim* `Role` igual a ==normal== terá acesso a rota.

> Observe que todos os métodos sempre acessam a camada de serviços e não as outras camadas (*repository*, *authorization*, etc.) diretamente.

Vejamos a seguir o `UserController`:

```C#
using AuthAPI.Models;
using AuthAPI.Models.DTO;
using AuthAPI.Services.Interfaces;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace AuthAPI.Controllers {
    [ApiController]
    [Route("api/[controller]")]
    public class UserController : ControllerBase {
        
        private readonly IUserService _userService;

        public UserController(IUserService userService) {
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
        public IActionResult Signin([FromBody] LoginDTO loginDTO) {
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
        /// <param name="tokenDTO">Token de Acesso e RefreshToken:</param>
        /// <returns>Novo Token retornado</returns>
        /// <response code="200">OK - Novo Token Gerado</response>
        /// <response code="400">BadRequest - Requisição do Cliente é Inválida</response>
        [HttpPost("refresh")]
        [ProducesResponseType(StatusCodes.Status200OK, Type = typeof(TokenDTO))]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        public IActionResult Refresh([FromBody] TokenDTO tokenDTO) {   
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
        public IActionResult Revoke() {   
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
        public IActionResult IsAuthenticated() {
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
        public IActionResult IsAdmin() {
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
        public IActionResult IsNormal() {
            return Ok("Hello " + User.Identity.Name+", you are normal user!");
        }
    }
}
```

Para identificar os tipos de usuários do sistema, foi criada a classe estática `Roles`:

```C#
namespace AuthAPI.Models
{
    public static class Roles
    {
        public const string Admin = "admin";
        public const string Normal = "normal";
    }
}
```



# 4. Referências

[.NET - Apresentando o padrão Repository (macoratti.net)](http://www.macoratti.net/11/10/net_pr1.htm)

[.NET 5.0 - Role Based Authorization Tutorial with Example API | Jason Watmore's Blog](https://jasonwatmore.com/post/2021/07/29/net-5-role-based-authorization-tutorial-with-example-api)
