using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using IdentityModel;
using IdentityModel.Client;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace demo_oidc_web_client
{
    public class SimpleOpenIdConnectProtocolValidator : OpenIdConnectProtocolValidator
    {
        public override string GenerateNonce()
        {
            return Guid.NewGuid().ToString();
        }

    }
    public class NeedsServiceProviderOpenIdConnectProtocolValidator : OpenIdConnectProtocolValidator
    {
        private IServiceProvider _sp;

        public NeedsServiceProviderOpenIdConnectProtocolValidator(IServiceProvider sp)
        {
            _sp = sp;
        }
        public override string GenerateNonce()
        {
            var httpAccessor = _sp.GetRequiredService<IHttpContextAccessor>();
            return Guid.NewGuid().ToString();
        }

    }
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
            JwtSecurityTokenHandler.DefaultInboundClaimTypeMap.Clear();
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddHttpContextAccessor();
            var authority = Configuration["oidc:authority"];

            services.AddControllersWithViews();
            services.AddHttpClient();
            services.AddSingleton<IDiscoveryCache>(r =>
            {
                var factory = r.GetRequiredService<IHttpClientFactory>();
                return new DiscoveryCache(authority, () => factory.CreateClient());
            });

            services.AddOptions<OpenIdConnectOptions>("oidc")
                       .Configure<IServiceProvider>((options, sp) =>
                       {
                           options.ProtocolValidator = new NeedsServiceProviderOpenIdConnectProtocolValidator(sp)
                           {
                               RequireTimeStampInNonce = false,
                               RequireStateValidation = false,
                               RequireNonce = true,
                               NonceLifetime = TimeSpan.FromMinutes(15)
                           };
                       });

            services.AddAuthentication(options =>
            {
                options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = "oidc";
            })
            .AddCookie(options =>
            {
                options.ExpireTimeSpan = TimeSpan.FromMinutes(60);
                options.Cookie.Name = "mvchybrid";
            })
            .AddOpenIdConnect("oidc", options =>
            {   
                // however, this works but no HttpContext
                /*
                options.ProtocolValidator = new SimpleOpenIdConnectProtocolValidator()
                {
                    RequireTimeStampInNonce = false,
                    RequireStateValidation = false,
                    RequireNonce = true,
                    NonceLifetime = TimeSpan.FromMinutes(15)
                };
*/
                options.Authority = authority;
                options.RequireHttpsMetadata = false;

                options.ClientId = "server.code";
                options.ClientSecret = "secret";

                options.ResponseType = "code";

                options.Scope.Clear();
                options.Scope.Add("openid");
                options.Scope.Add("profile");


                options.ClaimActions.MapAllExcept("iss", "nbf", "exp", "aud", "nonce", "iat", "c_hash");

                options.GetClaimsFromUserInfoEndpoint = true;
                options.SaveTokens = true;

                options.TokenValidationParameters = new TokenValidationParameters
                {
                    NameClaimType = JwtClaimTypes.Name,
                    RoleClaimType = JwtClaimTypes.Role,
                };
                options.Events.OnTicketReceived = context =>
                {


                    return Task.FromResult(0);
                };
                options.Events.OnAuthorizationCodeReceived = context =>
                {


                    return Task.FromResult(0);
                };
                options.Events.OnMessageReceived = context =>
                {


                    return Task.FromResult(0);
                };
            });
        }
        static bool ValidateCertificate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors errors)
        {
            return true;
        }
        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }
           
            app.UseStaticFiles();

            app.UseRouting();

            app.UseAuthentication();
            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllerRoute(
                    name: "default",
                    pattern: "{controller=Home}/{action=Index}/{id?}");
            });
        }
    }
}
