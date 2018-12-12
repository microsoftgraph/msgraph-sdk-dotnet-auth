// ------------------------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All Rights Reserved.  Licensed under the MIT License.  See License in the project root for license information.
// ------------------------------------------------------------------------------

namespace Microsoft.Graph.Auth
{
    using System.Net.Http;
    using System.Threading.Tasks;
    using Microsoft.Identity.Client;
    public class AuthorizationCodeProvider : MsalAuthenticationBase, IAuthenticationProvider
    {
        public string ClientId { get; }
        public string Authority { get; }
        public string RedirectUri { get; }
        public ClientCredential ClientCredential { get; }
        public ITokenCacheStorage UserTokenCache { get; }

        public AuthorizationCodeProvider(
            IConfidentialClientApplication confidentialClientApplication,
            string[] scopes)
            : base(scopes)
        {
            ClientApplication = confidentialClientApplication;
        }

        public AuthorizationCodeProvider(
            string clientId,
            string redirectUri,
            ClientCredential clientCredential,
            ITokenCacheStorage userTokenCache,
            string[] scopes)
            : base(scopes)
        {
            ClientId = clientId;
            RedirectUri = redirectUri;
            ClientCredential = clientCredential;
            UserTokenCache = userTokenCache;
        }

        public AuthorizationCodeProvider(
            string clientId,
            string authority,
            string redirectUri,
            ClientCredential clientCredential,
            ITokenCacheStorage userTokenCache,
            string[] scopes)
            : base(scopes)
        {
            ClientId = clientId;
            Authority = authority;
            RedirectUri = redirectUri;
            ClientCredential = clientCredential;
            UserTokenCache = userTokenCache;
        }

        public async Task AuthenticateRequestAsync(HttpRequestMessage httpRequestMessage)
        {
            if(ClientApplication == null)
            {
                if(Authority == null)
                    ClientApplication = new ConfidentialClientApplication(ClientId, RedirectUri, ClientCredential, UserTokenCache.GetTokenCacheInstance(), null);
                else
                    ClientApplication = new ConfidentialClientApplication(ClientId, Authority, RedirectUri, ClientCredential, UserTokenCache.GetTokenCacheInstance(), null);
            }

            await AddTokenToRequestAsync(httpRequestMessage);
        }

        internal override async Task<AuthenticationResult> GetNewAccessTokenAsync()
        {
            await Task.FromResult(0);
            throw new MsalUiRequiredException(MsalAuthErrorConstants.Codes.AuthenticationChallengeRequired, MsalAuthErrorConstants.Message.AuthenticationChallengeRequired);
        }
    }
}
