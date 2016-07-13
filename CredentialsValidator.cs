using System.Threading.Tasks;
using Microsoft.AspNet.Identity;
using Microsoft.Owin.Security.OAuth;

namespace DevTeam.BearerAuthentication
{
    public class CredentialsValidator<TUser, TService> : OAuthBaseValidator<OAuthGrantResourceOwnerCredentialsContext, TUser, TService>
        where TUser: class, IUser
        where TService: UserManager<TUser>
    {
        public CredentialsValidator(OAuthGrantResourceOwnerCredentialsContext context)
            : base(context)
        { }

        public override async Task<TUser> GetUser()
        {
            return await Service.FindAsync(Context.UserName, Context.Password);
        }
    }
}
