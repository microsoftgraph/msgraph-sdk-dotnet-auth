// ------------------------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All Rights Reserved.  Licensed under the MIT License.  See License in the project root for license information.
// ------------------------------------------------------------------------------

namespace Microsoft.Graph.Auth
{
    using System.Threading.Tasks;
    using Microsoft.Identity.Client;
    using System.Net.Http;
    using System.Net.Http.Headers;
    using System;
    using System.Threading;

#if NET45 || NET_CORE
    // Works for tenanted & work & school accounts
    // Only available on .Net & .Net core and UWP
    /// <summary>
    /// An <see cref="IAuthenticationProvider"/> implementation using MSAL.Net to acquire token by integrated windows authentication.
    /// </summary>
    public class IntegratedWindowsAuthenticationProvider : MsalAuthenticationBase, IAuthenticationProvider
    {
        private string Username;

        /// <summary>
        /// Constructs a new <see cref="IntegratedWindowsAuthenticationProvider"/>
        /// </summary>
        /// <param name="publicClientApplication">A <see cref="PublicClientApplication"/> to pass to <see cref="DeviceCodeProvider"/> for authentication</param>
        /// <param name="scopes">Scopes required to access a protected API</param>
        public IntegratedWindowsAuthenticationProvider(
           IPublicClientApplication publicClientApplication,
           string[] scopes)
           : base(scopes)
        {
            ClientApplication = publicClientApplication;
        }

#if !NET_CORE
        /// <summary>
        /// Constructs a new <see cref="IntegratedWindowsAuthenticationProvider"/>
        /// </summary>
        /// <param name="publicClientApplication">A <see cref="PublicClientApplication"/> to pass to <see cref="DeviceCodeProvider"/> for authentication</param>
        /// <param name="scopes">Scopes required to access a protected API</param>
        /// <param name="username">Identifier of the user account for which to acquire a token with Integrated Windows authentication. 
        /// Generally in UserPrincipalName (UPN) format, e.g. john.doe@contoso.com</param>
        public IntegratedWindowsAuthenticationProvider(
           IPublicClientApplication publicClientApplication,
           string[] scopes,
           string username)
           : base(scopes)
        {
            ClientApplication = publicClientApplication;
            Username = username;
        }
#endif
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
            IPublicClientApplication publicClientApplication = (ClientApplication as IPublicClientApplication);
            int retryCount = 0;
            do
            {
                try
                {
                    if (Username != null)
                        authenticationResult = await publicClientApplication.AcquireTokenByIntegratedWindowsAuthAsync(Scopes, Username);
                    else
                        authenticationResult = await publicClientApplication.AcquireTokenByIntegratedWindowsAuthAsync(Scopes);
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
#endif
}
