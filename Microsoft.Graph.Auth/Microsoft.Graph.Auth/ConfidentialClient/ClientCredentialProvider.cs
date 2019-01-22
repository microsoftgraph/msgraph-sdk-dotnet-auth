// ------------------------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All Rights Reserved.  Licensed under the MIT License.  See License in the project root for license information.
//

namespace Microsoft.Graph.Auth
{
    using Microsoft.Identity.Client;
    using System;
    using System.Net.Http;
    using System.Net.Http.Headers;
    using System.Threading.Tasks;

    /// <summary>
    /// An <see cref="IAuthenticationProvider"/> implementation using MSAL.Net to acquire token by client credential flow.
    /// </summary>
    public class ClientCredentialProvider : MsalAuthenticationBase, IAuthenticationProvider
    {
        private const string ResourceUrl = "https://graph.microsoft.com/.default";

        /// <summary>
        /// Constructs a new <see cref=" ClientCredentialProvider"/>
        /// </summary>
        /// <param name="confidentialClientApplication">A <see cref="ConfidentialClientApplication"/> to pass to <see cref="ClientCredentialProvider"/> for authentication</param>
        /// <param name="scopes">Scopes required to access a protected API</param>
        public ClientCredentialProvider(
            IConfidentialClientApplication confidentialClientApplication,
            string[] scopes)
            : base(scopes)
        {
            ClientApplication = confidentialClientApplication;
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
            int retryCount = 0;
            do
            {
                try
                {
                    AuthenticationResult authenticationResult = await GetNewAccessTokenAsync(httpRequestMessage, forceRefresh);
                    httpRequestMessage.Headers.Authorization = new AuthenticationHeaderValue(CoreConstants.Headers.Bearer, authenticationResult?.AccessToken);
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
        }

        private async Task<AuthenticationResult> GetNewAccessTokenAsync(HttpRequestMessage httpRequestMessage, bool forceRefresh)
        {
            AuthenticationResult authenticationResult = await (ClientApplication as IConfidentialClientApplication).AcquireTokenForClientAsync(new string[] { ResourceUrl }, forceRefresh);

            return authenticationResult;
        }
    }
}
