// ------------------------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All Rights Reserved.  Licensed under the MIT License.  See License in the project root for license information.
// ------------------------------------------------------------------------------

namespace Microsoft.Graph.Auth
{
    using System.Net.Http;
    using System.Threading.Tasks;
    using Microsoft.Identity.Client;

    public class OnBehalfOfProvider : MsalAuthenticationBase, IAuthenticationProvider
    {
        private UserAssertion UserAssertion;
        public OnBehalfOfProvider(
            ConfidentialClientApplication confidentialClientApplication,
            string[] scopes,
            UserAssertion userAssertion)
            : base(scopes)
        {
            ClientApplication = confidentialClientApplication;
            UserAssertion = userAssertion;
        }

        public OnBehalfOfProvider(
            string clientId,
            string redirectUri,
            ClientCredential clientCredential,
            TokenCache userTokenCache,
            string[] scopes,
            UserAssertion userAssertion)
            : base(scopes)
        {
            ClientApplication = new ConfidentialClientApplication(clientId, redirectUri, clientCredential, userTokenCache, null);
            UserAssertion = userAssertion;
        }

        public OnBehalfOfProvider(
            string clientId,
            string authority,
            string redirectUri,
            ClientCredential clientCredential,
            TokenCache userTokenCache,
            string[] scopes,
            UserAssertion userAssertion)
            : base(scopes)
        {
            ClientApplication = new ConfidentialClientApplication(clientId, authority, redirectUri, clientCredential, userTokenCache, null);
            UserAssertion = userAssertion;
        }

        public async Task AuthenticateRequestAsync(HttpRequestMessage request)
        {
            await AddTokenToRequestAsync(request);
        }

        internal override async Task<AuthenticationResult> GetNewAccessTokenAsync()
        {
            IConfidentialClientApplication confidentialClientApplication = (IConfidentialClientApplication) ClientApplication;

            AuthenticationResult authResult = await confidentialClientApplication.AcquireTokenOnBehalfOfAsync(Scopes, UserAssertion, ClientApplication.Authority);

            return authResult;
        }
    }
}
