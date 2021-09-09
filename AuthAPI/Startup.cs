using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Text;
using AuthAPI.Authorization;
using AuthAPI.Authorization.Interfaces;
using AuthAPI.Models.Configuration;
using AuthAPI.Models.Context;
using AuthAPI.Repository;
using AuthAPI.Repository.Interfaces;
using AuthAPI.Services;
using AuthAPI.Services.Interfaces;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;

namespace AuthAPI
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {

            services.AddControllers();

            //////////////////////////////////
            // CONFIGURE TokenConfiguration //
            //////////////////////////////////
            // GET FROM appsettings.json. SAVE TO TokenConfiguration
            TokenConfiguration configuration = new TokenConfiguration();    
            new ConfigureFromConfigurationOptions<TokenConfiguration>(      
                Configuration.GetSection("TokenConfigurations")
            ).Configure(configuration);
            // INJECTING DEPENDENCY
            services.AddSingleton(configuration);

            //////////////////////////////
            // CONFIGURE AUTHENTICATION //
            //////////////////////////////
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

            ////////////////////////////
            // CONFIGURE Swagger Docs //
            ////////////////////////////
            services.AddSwaggerGen(c =>
            {
                c.SwaggerDoc("v1", new OpenApiInfo { 
                    Title = "Authentication and Authorization .NET5 (Base)", 
                    Version = "v1",
                    Description = "Base project for authentication and authorization with Roles, UserManager, RefreshToken and Revoke",
                    Contact = new OpenApiContact {
                        Name = "Ellison Guimarães",
                        Email = "ellison.guimaraes@gmail.com",
                        Url = new Uri("https://github.com/ellisonguimaraes")
                    }
                });

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

                // Configure XML Comments to Swagger
                var xmlFile = $"{Assembly.GetExecutingAssembly().GetName().Name}.xml";
                var xmlPath = Path.Combine(AppContext.BaseDirectory, xmlFile);
                c.IncludeXmlComments(xmlPath);
            });

            ////////////////////////////////////
            // EntityFramework Inject Context //
            ////////////////////////////////////
            var connectionString = Configuration["ConnectionStrings:MySQLConnectionString"];
            services.AddDbContext<ApplicationContext>(options =>  options.UseMySql(connectionString, 
                                                                        ServerVersion.AutoDetect(connectionString)));
            ///////////////////////////////
            // Injection Dependency (DI) //
            ///////////////////////////////
            services.AddScoped<IUserRepository, UserRepository>();
            services.AddScoped<IJwTUtils, JwTUtils>();
            services.AddScoped<IUserService, UserService>();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            app.UseHttpsRedirection();

            app.UseRouting();

            // USE MIDDLEWARE JwTMiddleware
            app.UseMiddleware<JwTMiddleware>();
            
            // USE AUTHENTICATION (1)
            app.UseAuthentication();

            // USE AUTHORIZATION (2)
            app.UseAuthorization();
            
            // USE SWAGGER
            app.UseSwagger();
            app.UseSwaggerUI(c => {
                c.RoutePrefix = string.Empty;
                c.SwaggerEndpoint("/swagger/v1/swagger.json", "Authentication and Authorization .NET5 (Base)");
            });

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
            });
        }
    }
}
