// ------------------------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All Rights Reserved.  Licensed under the MIT License.  See License in the project root for license information.
// ------------------------------------------------------------------------------

namespace Microsoft.Graph.Auth
{
    using System.Net.Http;
    using System.Threading.Tasks;
    using Microsoft.Identity.Client;
    public class AuthenticationCodeFlowProvider : MsalAuthenticationBase, IAuthenticationProvider
    {
        public AuthenticationCodeFlowProvider(ConfidentialClientApplication confidentialClientApplication, string[] scopes)
            : base(scopes)
        {
            ClientApplication = confidentialClientApplication;
        }

        public AuthenticationCodeFlowProvider(
            string clientId,
            string redirectUri,
            ClientCredential clientCredential,
            TokenCache userTokenCache,
            string[] scopes)
            : base(scopes)
        {
            ClientApplication = new ConfidentialClientApplication(clientId, redirectUri, clientCredential, userTokenCache, null);
        }

        public AuthenticationCodeFlowProvider(
            string clientId,
            string authority,
            string redirectUri,
            ClientCredential clientCredential,
            TokenCache userTokenCache,
            string[] scopes)
            : base(scopes)
        {
            ClientApplication = new ConfidentialClientApplication(clientId, authority, redirectUri, clientCredential, userTokenCache, null);
        }

        public async Task AuthenticateRequestAsync(HttpRequestMessage httpRequestMessage)
        {
            await AddTokenToRequestAsync(httpRequestMessage);
        }

        internal override async Task<AuthenticationResult> GetNewAccessTokenAsync()
        {
            await Task.FromResult(0);
            // TODO: perform a platform specific challenge
            // we can thrown a challenge required exception back to the user
            throw new MsalUiRequiredException(MsalAuthErrorConstants.Codes.AuthenticationChallengeRequired, MsalAuthErrorConstants.Message.AuthenticationChallengeRequired);
        }
    }
}
