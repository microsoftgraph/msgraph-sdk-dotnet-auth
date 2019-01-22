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
        /// <summary>
        /// Construct a new <see cref="AuthorizationCodeProvider"/>
        /// </summary>
        /// <param name="confidentialClientApplication">A <see cref="ConfidentialClientApplication"/> to pass to <see cref="AuthorizationCodeProvider"/> for authentication</param>
        /// <param name="scopes">Scopes required to access a protected API</param>
        public AuthorizationCodeProvider(
            IConfidentialClientApplication confidentialClientApplication,
            string[] scopes)
            : base(scopes)
        {
            ClientApplication = confidentialClientApplication;
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
            //TODO: Get ForceRefresh via RequestContext
            //TODO: Get Scopes via RequestContext
            bool forceRefresh = false;

            AuthenticationResult authenticationResult = await this.GetAccessTokenSilentAsync(Scopes, forceRefresh);

            if (authenticationResult == null)
            {
                throw new MsalServiceException(MsalAuthErrorConstants.Codes.AuthenticationChallengeRequired, MsalAuthErrorConstants.Message.AuthenticationChallengeRequired);
            }

            httpRequestMessage.Headers.Authorization = new AuthenticationHeaderValue(CoreConstants.Headers.Bearer, authenticationResult.AccessToken);
        }
    }
}
