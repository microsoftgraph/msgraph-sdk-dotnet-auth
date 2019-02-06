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
    using Microsoft.Graph.Auth.Helpers;

#if NET45 || NET_CORE
    // Works for tenanted & work & school accounts
    // Only available on .Net & .Net core and UWP
    /// <summary>
    /// An <see cref="IAuthenticationProvider"/> implementation using MSAL.Net to acquire token by integrated windows authentication.
    /// </summary>
    public class IntegratedWindowsAuthenticationProvider : MsalAuthenticationBase, IAuthenticationProvider
    {
        private string _username;

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
            //TODO: Move to AuthProviderOption
            _username = username;
        }
#endif

        /// <summary>
        /// Creates a new <see cref="PublicClientApplication"/>
        /// </summary>
        /// <param name="clientId">Client ID (also known as <i>Application ID</i>) of the application as registered in the application registration portal (https://aka.ms/msal-net-register-app)</param>
        /// <param name="tokenStorageProvider">A <see cref="ITokenStorageProvider"/> for storing and retrieving access token. </param>
        /// <param name="tenant">Tenant to sign-in users. This defaults to <c>organizations</c> if non is specified. </param>
        /// <param name="nationalCloud">A <see cref="NationalCloud"/> which identifies the national cloud endpoint to use as the authority. This defaults to the global cloud <see cref="NationalCloud.Global"/> (https://login.microsoftonline.com) </param>
        /// <returns>A <see cref="PublicClientApplication"/></returns>
        public static PublicClientApplication CreateClientApplication(string clientId,
            ITokenStorageProvider tokenStorageProvider = null,
            string tenant = null,
            NationalCloud nationalCloud = NationalCloud.Global)
        {
            TokenCacheProvider tokenCacheProvider = new TokenCacheProvider(tokenStorageProvider);
            string authority = NationalCloudHelpers.GetAuthority(nationalCloud, tenant ?? AuthConstants.Tenants.Organizations);
            return new PublicClientApplication(clientId, authority, tokenCacheProvider.GetTokenCacheInstnce());
        }

        /// <summary>
        /// Adds an authentication header to the incoming request by checking the application's <see cref="TokenCache"/>
        /// for an unexpired access token. If a token is not found or expired, it gets a new one.
        /// </summary>
        /// <param name="httpRequestMessage">A <see cref="HttpRequestMessage"/> to authenticate</param>
        public async Task AuthenticateRequestAsync(HttpRequestMessage httpRequestMessage)
        {
            //TODO: Get ForceRefresh via RequestContext
            //TODO: Get Scopes via AuthProviderOption
            //TODO: Get Username via AuthProviderOption
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
                    if (_username != null)
                        authenticationResult = await publicClientApplication.AcquireTokenByIntegratedWindowsAuthAsync(Scopes, _username);
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
