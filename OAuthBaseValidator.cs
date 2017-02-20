using System.Collections.Generic;
using System.Net;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.OAuth;

namespace DevTeam.BearerAuthentication
{
    public abstract class OAuthBaseValidator<TContext, TUser, TService>
        where TContext : BaseValidatingTicketContext<OAuthAuthorizationServerOptions>
        where TUser: class, IUser
        where TService: UserManager<TUser>
    {
        protected readonly TContext Context;

        protected virtual TService Service => Context.OwinContext.GetUserManager<TService>();

        protected OAuthBaseValidator(TContext context)
        {
            Context = context;
        }

        public abstract Task<TUser> GetUser();

        public virtual void AddClaims(ClaimsIdentity identity) { }

        public virtual async Task SignIn()
        {
            var user = await GetUser();

            if (user == null)
            {
                Context.Response.StatusCode = (int) HttpStatusCode.Unauthorized;
                return;
            }

            var bearerIdentity = await Service.CreateIdentityAsync(user, OAuthDefaults.AuthenticationType);

            AddClaims(bearerIdentity);

            var properties = new AuthenticationProperties(new Dictionary<string, string> { { "userName", user.UserName } });
            var ticket = new AuthenticationTicket(bearerIdentity, properties);
            Context.Validated(ticket);
            Context.Request.Context.Authentication.SignIn(bearerIdentity);
        }
    }
}
