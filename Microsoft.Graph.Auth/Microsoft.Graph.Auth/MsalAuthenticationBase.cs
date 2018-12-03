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
    /// Abstract class containing common API methods and properties to retreive an access token. The providers extend this class
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
        /// Attepmts to acquire access token form the token cache by calling AcquireTokenSilentAsync
        /// </summary>
        /// <returns></returns>
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
                catch (MsalUiRequiredException)
                {
                }
            }
            return authenticationResult;
        }

        /// <summary>
        /// Decides whether to use an access token from the token cache or requests a new access token
        /// </summary>
        /// <returns></returns>
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
        /// Adds access token to <see cref="HttpRequestMessage"/> authorization hrader
        /// </summary>
        /// <param name="httpRequestMessage"></param>
        /// <returns></returns>
        internal async Task AddTokenToRequestAsync(HttpRequestMessage httpRequestMessage, bool skipSilentTokenCheck = false)
        {
            AuthenticationResult authenticationResult = await GetAccessTokenAsync(skipSilentTokenCheck).ConfigureAwait(false);
            if (authenticationResult != null)
                httpRequestMessage.Headers.Authorization = new AuthenticationHeaderValue(CoreConstants.Headers.Bearer, authenticationResult.AccessToken);
        }

        /// <summary>
        /// Abstract function that will be overriden by the respective authorization flow providers to specify how to retreive new access tokens
        /// </summary>
        /// <returns></returns>
        internal abstract Task<AuthenticationResult> GetNewAccessTokenAsync();
    }
}
