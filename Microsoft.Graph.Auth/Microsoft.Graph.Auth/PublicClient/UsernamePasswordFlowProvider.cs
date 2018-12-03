// ------------------------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All Rights Reserved.  Licensed under the MIT License.  See License in the project root for license information.
// ------------------------------------------------------------------------------

namespace Microsoft.Graph.Auth
{
    using System.Net.Http;
    using System.Security;
    using System.Threading.Tasks;
    using Microsoft.Identity.Client;
#if NET45 || NET_CORE
    // Works for work & school accounts
    // Only available on .Net & .Net core, not available for UWP
    public class UsernamePasswordFlowProvider : MsalAuthenticationBase, IAuthenticationProvider
    {
        private string Username;
        private SecureString SecurePassword;
        public UsernamePasswordFlowProvider(
            PublicClientApplication publicClientApplication,
            string[] scopes,
            string username,
            SecureString securePassword)
            : base(scopes)
        {
            ClientApplication = publicClientApplication;
            Username = username;
            SecurePassword = securePassword;
        }

        public UsernamePasswordFlowProvider(
            string clientId,
            string authority,
            string[] scopes,
            string username,
            SecureString securePassword)
            : base(scopes)
        {
            ClientApplication = new PublicClientApplication(clientId, authority);
            Username = username;
            SecurePassword = securePassword;
        }

        public UsernamePasswordFlowProvider(
            string clientId,
            string authority,
            TokenCache userTokenCache,
            string[] scopes,
            string username,
            SecureString securePassword)
            : base(scopes)
        {
            ClientApplication = new PublicClientApplication(clientId, authority, userTokenCache);
            Username = username;
            SecurePassword = securePassword;
        }

        public async Task AuthenticateRequestAsync(HttpRequestMessage request)
        {
            await AddTokenToRequestAsync(request);
        }

        internal override async Task<AuthenticationResult> GetNewAccessTokenAsync()
        {
            IPublicClientApplication publicClientApplication = (IPublicClientApplication)ClientApplication;

            AuthenticationResult authResult = await publicClientApplication.AcquireTokenByUsernamePasswordAsync(Scopes, Username, SecurePassword);

            return authResult;
        }
    }
#endif
}
