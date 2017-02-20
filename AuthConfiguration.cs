using System;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin;
using Microsoft.Owin.Security.OAuth;
using Owin;

namespace DevTeam.BearerAuthentication
{
    public class AuthConfiguration<TUser, TUserManager>
        where TUser: class, IUser
        where TUserManager: UserManager<TUser>
    {
        private readonly Func<TUserManager> _serviceFunc;

        public AuthConfiguration(Func<TUserManager> serviceFunc)
        {
            _serviceFunc = serviceFunc;
        }

        protected TUserManager Create(IdentityFactoryOptions<TUserManager> options, IOwinContext context)
        {
            var manager = _serviceFunc();
            var dataProtectionProvider = options.DataProtectionProvider;
            if (dataProtectionProvider != null)
            {
                manager.UserTokenProvider = new DataProtectorTokenProvider<TUser>(dataProtectionProvider.Create("ASP.NET Identity"));
            }
            return manager;
        }

        public void Configure(IAppBuilder app, string tokenEndpoint = "/Token", string externalEndpoint = "/api/Account/ExternalLogin", int expiredTime = 14, bool allowInsecureHttp = true)
        {
            app.CreatePerOwinContext<TUserManager>(Create);
            app.UseOAuthBearerTokens(new OAuthAuthorizationServerOptions
            {
                TokenEndpointPath = new PathString(tokenEndpoint),
                Provider = new ApplicationOAuthProvider<TUser, TUserManager>("self"),
                AuthorizeEndpointPath = new PathString(externalEndpoint),
                AccessTokenExpireTimeSpan = TimeSpan.FromDays(expiredTime),
                AllowInsecureHttp = allowInsecureHttp
            });
        }
    }
}
