// ------------------------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All Rights Reserved.  Licensed under the MIT License.  See License in the project root for license information.
// ------------------------------------------------------------------------------

namespace Microsoft.Graph.Auth
{
    using System;
    using System.Net.Http;
    using System.Net.Http.Headers;
    using System.Security;
    using System.Threading.Tasks;
    using Microsoft.Identity.Client;
#if NET45 || NET_CORE
    // Works for work & school accounts
    // Only available on .Net & .Net core, not available for UWP
    /// <summary>
    /// An <see cref="IAuthenticationProvider"/> implementation using MSAL.Net to acquire token by username and password.
    /// </summary>
    public class UsernamePasswordProvider : MsalAuthenticationBase, IAuthenticationProvider
    {
        private string Username;
        private SecureString SecurePassword;

        /// <summary>
        /// Constructs a new <see cref="UsernamePasswordProvider"/>
        /// </summary>
        /// <param name="publicClientApplication">A <see cref="PublicClientApplication"/> to pass to <see cref="DeviceCodeProvider"/> for authentication</param>
        /// <param name="scopes">Scopes required to access a protected API</param>
        /// <param name="username">Identifier of the user application requests token on behalf.
        /// Generally in UserPrincipalName (UPN) format, e.g. john.doe@contoso.com</param>
        /// <param name="securePassword">A <see cref="SecureString"/> representing a user password</param>
        public UsernamePasswordProvider(
            IPublicClientApplication publicClientApplication,
            string[] scopes,
            string username,
            SecureString securePassword)
            : base(scopes)
        {
            ClientApplication = publicClientApplication;
            Username = username;
            SecurePassword = securePassword;
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
                    authenticationResult = await (ClientApplication as IPublicClientApplication).AcquireTokenByUsernamePasswordAsync(Scopes, Username, SecurePassword);
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
                        throw serviceException;
                }

            } while (retryCount < MaxRetry);

            return authenticationResult;
        }
    }
#endif
}
