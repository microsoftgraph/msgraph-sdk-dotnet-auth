// ------------------------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All Rights Reserved.  Licensed under the MIT License.  See License in the project root for license information.
// ------------------------------------------------------------------------------

namespace Microsoft.Graph.Auth
{
    using Microsoft.Identity.Client;
    using System.Collections.Generic;
    using System.Linq;
    using System.Net.Http;
    using System.Threading.Tasks;
    using System.Net.Http.Headers;
    using System;
    /// <summary>
    /// Abstract class containing common API methods and properties to retreive an access token. All authentication providers extend this class
    /// </summary>
    public abstract class MsalAuthenticationBase
    {
        /// <summary>
        /// A <see cref="ClientApplicationBase"/> property
        /// </summary>
        internal IClientApplicationBase ClientApplication { get; set; }

        /// <summary>
        /// A scopes property
        /// </summary>
        internal string[] Scopes { get; }

        /// <summary>
        /// Constructs a new <see cref="MsalAuthenticationBase"/>
        /// </summary>
        /// <param name="scopes">Scopes requested to access a protected API</param>
        public MsalAuthenticationBase(string[] scopes)
        {
            Scopes = scopes;
        }

        /// <summary>
        /// Attempts to acquire access token form the token cache silently by calling AcquireTokenSilentAsync
        /// </summary>
        private async Task<AuthenticationResult> GetAccessTokenSilentAsync()
        {
            AuthenticationResult authenticationResult = null;
            IEnumerable<IAccount> users = await ClientApplication.GetAccountsAsync();
            if (users.Any())
            {
                try
                {
                    authenticationResult = await ClientApplication.AcquireTokenSilentAsync(Scopes, users.FirstOrDefault());
                }
                catch (Exception)
                {
                }
            }
            return authenticationResult;
        }

        /// <summary>
        /// Decides whether to use an access token from the token cache or requests a new access token
        /// </summary>>
        private async Task<AuthenticationResult> GetAccessTokenAsync(bool skipSilentTokenCheck)
        {
            AuthenticationResult authenticationResult = skipSilentTokenCheck ? null : await GetAccessTokenSilentAsync();
            if (authenticationResult == null)
            {
                authenticationResult = await GetNewAccessTokenAsync();
            }

            return authenticationResult;
        }

        /// <summary>
        /// Gets an access token and add's it to <see cref="HttpRequestMessage"/> authorization header
        /// </summary>
        /// <param name="httpRequestMessage"></param>
        internal async Task AddTokenToRequestAsync(HttpRequestMessage httpRequestMessage, bool skipSilentTokenCheck = false)
        {
            AuthenticationResult authenticationResult = await GetAccessTokenAsync(skipSilentTokenCheck).ConfigureAwait(false);
            if (authenticationResult != null)
                httpRequestMessage.Headers.Authorization = new AuthenticationHeaderValue(CoreConstants.Headers.Bearer, authenticationResult.AccessToken);
        }

        /// <summary>
        /// Abstract method overriden by the derived class to specify how to retreive new access tokens
        /// </summary>
        internal abstract Task<AuthenticationResult> GetNewAccessTokenAsync();
    }
}
