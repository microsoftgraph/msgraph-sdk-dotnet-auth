using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Identity.Client;

namespace Microsoft.Graph.Auth
{
#if NET45 || NET_CORE
    public class IntergratedWindowsAuthFlowProvider : MsalAuthenticationBase, IAuthenticationProvider
    {
        private string _username;
        public IntergratedWindowsAuthFlowProvider(PublicClientApplication clientApplication, string[] scopes) : base(clientApplication, scopes)
        {
        }

#if !NET_CORE
        public IntergratedWindowsAuthFlowProvider(PublicClientApplication clientApplication, string[] scopes, string username) : base(clientApplication, scopes)
        {
            _username = username;
        }
#endif
        public async Task AuthenticateRequestAsync(HttpRequestMessage request)
        {
            await AddTokenToRequestAsync(request);
        }

        internal override async Task<string> GetNewAccessTokenAsync()
        {
            AuthenticationResult authResult = null;
            PublicClientApplication publicClientApplication = (ClientApplication) as PublicClientApplication;

            if (_username != null)
                authResult = await publicClientApplication.AcquireTokenByIntegratedWindowsAuthAsync(Scopes, _username);
            else
                authResult = await publicClientApplication.AcquireTokenByIntegratedWindowsAuthAsync(Scopes);

            return authResult.AccessToken;
        }
    }
#endif
}
