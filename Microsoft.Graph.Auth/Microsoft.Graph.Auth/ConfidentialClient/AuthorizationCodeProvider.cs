// ------------------------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All Rights Reserved.  Licensed under the MIT License.  See License in the project root for license information.
// ------------------------------------------------------------------------------

namespace Microsoft.Graph.Auth
{
    using System.Net.Http;
    using System.Net.Http.Headers;
    using System.Threading.Tasks;
    using Microsoft.Identity.Client;

    /// <summary>
    /// An <see cref="IAuthenticationProvider"/> implementation using MSAL.Net to acquire token by authorization code flow.
    /// </summary>
    public class AuthorizationCodeProvider : MsalAuthenticationBase, IAuthenticationProvider
    {
        internal string RedirectUri { get; }
        internal ClientCredential ClientCredential { get; }
        internal ITokenCacheProvider UserTokenCache { get; }
        private string Authority { get; }
        /// <summary>
        /// Construct a new <see cref="AuthorizationCodeProvider"/>
        /// </summary>
        /// <param name="confidentialClientApplication">A <see cref="ConfidentialClientApplication"/> to pass to <see cref="AuthorizationCodeProvider"/> for authentication</param>
        /// <param name="scopes">Scopes required to access a protected API</param>
        public AuthorizationCodeProvider(
            IConfidentialClientApplication confidentialClientApplication,
            string[] scopes)
            : base(scopes, confidentialClientApplication.ClientId)
        {
            ClientApplication = confidentialClientApplication;
            RedirectUri = ClientApplication.RedirectUri;
        }

        /// <summary>
        /// Construct a new <see cref="AuthorizationCodeProvider"/>
        /// </summary>
        /// <param name="clientId">Client ID (also known as <i>Application ID</i>) of the application as registered in the application registration portal (https://aka.ms/msal-net-register-app)</param>
        /// <param name="redirectUri">also named <i>Reply URI</i>, the redirect URI is the URI where the STS (Security Token Service) will call back the application
        ///  with the security token. For details see https://aka.ms/msal-net-client-applications </param>
        /// <param name="clientCredential">A <see cref="Microsoft.Identity.Client.ClientCredential"/> created either from an application secret or a certificate</param>
        /// <param name="userTokenCacheProvider">A <see cref="ITokenCacheProvider"/> for storing access tokens.</param>
        /// <param name="scopes">Scopes required to access a protected API</param>
        /// <param name="nationalCloud">A <see cref="NationalCloud"/> which identifies the national cloud endpoint to use as the authority. This defaults to the global cloud <see cref="NationalCloud.Global"/> (https://login.microsoftonline.com) </param>
        /// <param name="tenant">Tenant to sign-in users.
        /// Usual tenants are :
        /// <list type="bullet">
        /// <item><description>Tenant ID of the Azure AD tenant or a domain associated with Azure AD tenant, to sign-in users of a specific organization only;</description></item>
        /// <item><description><c>common</c>, to sign-in users with any work and school accounts or Microsoft personal accounts;</description></item>
        /// <item><description><c>organizations</c>, to sign-in users with any work and school accounts;</description></item>
        /// <item><description><c>consumers</c>, to sign-in users with only personal Microsoft accounts(live);</description></item>
        /// </list>
        /// This defaults to <c>common</c>
        /// </param>
        public AuthorizationCodeProvider(
            string clientId,
            string redirectUri,
            ClientCredential clientCredential,
            ITokenCacheProvider userTokenCacheProvider,
            string[] scopes,
            NationalCloud nationalCloud = NationalCloud.Global,
            string tenant = null)
            : base(scopes, clientId)
        {
            RedirectUri = redirectUri;
            ClientCredential = clientCredential;
            UserTokenCache = userTokenCacheProvider;
            Authority = this.GetAuthority(nationalCloud, tenant ?? AuthConstants.Tenants.Common);
        }

        /// <summary>
        /// Adds an authentication header to the incoming request by checking the application's <see cref="TokenCache"/>
        /// for an unexpired access token.
        /// If an access token doesn't exist, it will throw a <see cref="MsalServiceException"/>
        /// and the web app must handle this and perform a challange
        /// </summary>
        /// <param name="httpRequestMessage">A <see cref="HttpRequestMessage"/> to authenticate</param>
        public async Task AuthenticateRequestAsync(HttpRequestMessage httpRequestMessage)
        {
            if (ClientApplication == null)
            {
                ClientApplication = new ConfidentialClientApplication(ClientId, Authority, RedirectUri, ClientCredential, UserTokenCache.GetTokenCacheInstance(), null);
            }

            AuthenticationResult authenticationResult = await this.GetAccessTokenSilentAsync();

            if (authenticationResult == null)
            {
                throw new MsalServiceException(MsalAuthErrorConstants.Codes.AuthenticationChallengeRequired, MsalAuthErrorConstants.Message.AuthenticationChallengeRequired);
            }

            httpRequestMessage.Headers.Authorization = new AuthenticationHeaderValue(CoreConstants.Headers.Bearer, authenticationResult.AccessToken);
        }
    }
}
