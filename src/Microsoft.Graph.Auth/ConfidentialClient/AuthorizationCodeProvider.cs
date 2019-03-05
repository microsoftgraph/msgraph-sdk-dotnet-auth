// ------------------------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All Rights Reserved.  Licensed under the MIT License.  See License in the project root for license information.
// ------------------------------------------------------------------------------

namespace Microsoft.Graph.Auth
{
    using System.Net.Http;
    using System.Net.Http.Headers;
    using System.Threading.Tasks;
    using Microsoft.Identity.Client;
    using Microsoft.Graph.Auth.Helpers;

    /// <summary>
    /// An <see cref="IAuthenticationProvider"/> implementation using MSAL.Net to acquire token by authorization code flow for web apps.
    /// </summary>
    public class AuthorizationCodeProvider : MsalAuthenticationBase, IAuthenticationProvider
    {
        /// <summary>
        /// Construct a new <see cref="AuthorizationCodeProvider"/>
        /// </summary>
        /// <param name="confidentialClientApplication"><see cref="IConfidentialClientApplication"/> used to authentication requests.</param>
        /// <param name="scopes">Scopes required to access Microsoft Graph.</param>
        public AuthorizationCodeProvider(
            IConfidentialClientApplication confidentialClientApplication,
            string[] scopes)
            : base(scopes)
        {
            ClientApplication = confidentialClientApplication ?? throw new GraphAuthException(
                    new Error
                    {
                        Code = ErrorConstants.Codes.InvalidRequest,
                        Message = string.Format(ErrorConstants.Message.NullValue, "confidentialClientApplication")
                    });
        }
        
        /// <summary>
        /// Creates a new <see cref="IConfidentialClientApplication"/>.
        /// </summary>
        /// <param name="clientId">Client ID (also known as <i>Application ID</i>) of the application as registered in the application registration portal (https://aka.ms/msal-net-register-app).</param>
        /// <param name="redirectUri">Also named <i>Reply URI</i>, the redirect URI is the URI where the STS (Security Token Service) will call back the application
        ///  with the security token. For details see https://aka.ms/msal-net-client-applications.</param>
        /// <param name="clientCredential">A <see cref="Microsoft.Identity.Client.ClientCredential"/> created either from an application secret or a certificate.</param>
        /// <param name="tokenStorageProvider">An <see cref="ITokenStorageProvider"/> for storing and retrieving access token. </param>
        /// <param name="tenant">Tenant to sign-in users. This defaults to <c>common</c> if non is specified.</param>
        /// <param name="nationalCloud">A <see cref="NationalCloud"/> which identifies the national cloud endpoint to use as the authority. This defaults to the global cloud <see cref="NationalCloud.Global"/> (https://login.microsoftonline.com).</param>
        /// <returns>A <see cref="IConfidentialClientApplication"/></returns>
        public static IConfidentialClientApplication CreateClientApplication(string clientId,
            string redirectUri,
            ClientCredential clientCredential,
            ITokenStorageProvider tokenStorageProvider = null,
            string tenant = null,
            NationalCloud nationalCloud = NationalCloud.Global)
        {
            TokenCacheProvider tokenCacheProvider = new TokenCacheProvider(tokenStorageProvider);
            string authority = NationalCloudHelpers.GetAuthority(nationalCloud, tenant ?? AuthConstants.Tenants.Common);
            return new ConfidentialClientApplication(clientId, authority, redirectUri, clientCredential, tokenCacheProvider.GetTokenCacheInstnce(), null);
        }

        /// <summary>
        /// Adds an authentication header to the incoming request by checking the application's <see cref="TokenCache"/>
        /// for an unexpired access token.
        /// If an access token doesn't exist, it will throw a <see cref="GraphAuthException"/>
        /// and the web app must handle this and perform a challange.
        /// </summary>
        /// <param name="httpRequestMessage">A <see cref="HttpRequestMessage"/> to authenticate.</param>
        public async Task AuthenticateRequestAsync(HttpRequestMessage httpRequestMessage)
        {
            MsalAuthProviderOption msalAuthProviderOption = httpRequestMessage.GetMsalAuthProviderOption();
            AuthenticationResult authenticationResult = await GetAccessTokenSilentAsync(msalAuthProviderOption);

            if (string.IsNullOrEmpty(authenticationResult?.AccessToken))
            {
                throw new GraphAuthException(
                    new Error
                    {
                        Code = ErrorConstants.Codes.AuthenticationChallengeRequired,
                        Message = ErrorConstants.Message.AuthenticationChallengeRequired
                    });
            }

            httpRequestMessage.Headers.Authorization = new AuthenticationHeaderValue(CoreConstants.Headers.Bearer, authenticationResult.AccessToken);
        }

        /// <summary>
        /// Helper used in Startup class to retrieve a token from an authorization code.
        /// </summary>
        /// <param name="authorizationCode">An authorization code received from an openid connect auth flow.</param>
        /// <returns></returns>
        public async Task<AuthenticationResult> GetTokenByAuthorizationCodeAsync(string authorizationCode)
        {
            return await (ClientApplication as IConfidentialClientApplication).AcquireTokenByAuthorizationCodeAsync(authorizationCode, Scopes);
        }
    }
}
