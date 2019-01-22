// ------------------------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All Rights Reserved.  Licensed under the MIT License.  See License in the project root for license information.
// ------------------------------------------------------------------------------

namespace Microsoft.Graph.Auth
{
    using System;
    using System.Net.Http;
    using System.Net.Http.Headers;
    using System.Threading.Tasks;
    using Microsoft.Identity.Client;

    /// <summary>
    /// An <see cref="IAuthenticationProvider"/> implementation using MSAL.Net to acquire token by on behalf of flow.
    /// </summary>
    public class OnBehalfOfProvider : MsalAuthenticationBase, IAuthenticationProvider
    {
        private UserAssertion UserAssertion;
        /// <summary>
        /// Constructs a new <see cref="OnBehalfOfProvider"/>
        /// </summary>
        /// <param name="confidentialClientApplication">A <see cref="ConfidentialClientApplication"/> to pass to <see cref="OnBehalfOfProvider"/> for authentication</param>
        /// <param name="scopes">Scopes required to access a protected API</param>
        /// <param name="userAssertion">Instance of <see cref="Microsoft.Identity.Client.UserAssertion"/> containing credential information about
        /// the user on behalf of whom to get a token.</param>
        public OnBehalfOfProvider(
            IConfidentialClientApplication confidentialClientApplication,
            string[] scopes,
            UserAssertion userAssertion)
            : base(scopes)
        {
            ClientApplication = confidentialClientApplication;
            UserAssertion = userAssertion;
        }

        /// <summary>
        /// Adds an authentication header to the incoming request by checking the application's <see cref="TokenCache"/>
        /// for an unexpired access token. If a token is not found or expired, it gets a new one.
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
                authenticationResult = await GetNewAccessTokenAsync();
            }

            httpRequestMessage.Headers.Authorization = new AuthenticationHeaderValue(CoreConstants.Headers.Bearer, authenticationResult.AccessToken);
        }

        private async Task<AuthenticationResult> GetNewAccessTokenAsync()
        {
            AuthenticationResult authenticationResult = null;
            int retryCount = 0;
            do
            {
                try
                {
                    authenticationResult = await(ClientApplication as IConfidentialClientApplication).AcquireTokenOnBehalfOfAsync(Scopes, UserAssertion, ClientApplication.Authority);
                    break;
                }
                catch (MsalServiceException serviceException)
                {
                    if (serviceException.ErrorCode == MsalAuthErrorConstants.Codes.TemporarilyUnavailable)
                    {
                        TimeSpan delay = this.GetRetryAfter(serviceException);
                        retryCount++;
                        // pause execution
                        await Task.Delay(delay);
                    }
                    else
                    {
                        throw serviceException;
                    }
                }

            } while (retryCount < MaxRetry);

            return authenticationResult;
        }
    }
}
