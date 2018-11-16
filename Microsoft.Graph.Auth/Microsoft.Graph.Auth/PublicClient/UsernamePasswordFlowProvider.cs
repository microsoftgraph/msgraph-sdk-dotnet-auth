using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Security;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Identity.Client;

namespace Microsoft.Graph.Auth
{
#if NET45
    public class UsernamePasswordFlowProvider : MsalAuthenticationBase, IAuthenticationProvider
    {
        private string _username;
        private SecureString _securePassword;

        public UsernamePasswordFlowProvider(PublicClientApplication clientApplication, string[] scopes, string username, SecureString securePassword) : base(clientApplication, scopes)
        {
            _username = username;
            _securePassword = securePassword;
        }

        public async Task AuthenticateRequestAsync(HttpRequestMessage request)
        {
            await AddTokenToRequestAsync(request);
        }

        internal override async Task<string> GetNewAccessTokenAsync()
        {
            AuthenticationResult authResult;
            PublicClientApplication publicClientApplication = ClientApplication as PublicClientApplication;

            authResult = await publicClientApplication.AcquireTokenByUsernamePasswordAsync(Scopes, _username, _securePassword);

            return authResult.AccessToken;
        }
    }
#endif
}
