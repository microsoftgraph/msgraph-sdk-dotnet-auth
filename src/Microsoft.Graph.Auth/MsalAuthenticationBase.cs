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
        /// A MaxRetry property
        /// </summary>
        internal int MaxRetry { get; set; } = 1;

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
        internal async Task<AuthenticationResult> GetAccessTokenSilentAsync(string[] scopes, bool forceRefresh)
        {
            AuthenticationResult authenticationResult = null;
            IEnumerable<IAccount> accounts = await ClientApplication.GetAccountsAsync();
            if (accounts.Any())
            {
                try
                {
                    authenticationResult = await ClientApplication.AcquireTokenSilentAsync(scopes, accounts.FirstOrDefault(), ClientApplication.Authority, forceRefresh);
                }
                catch (Exception)
                {
                }
            }
            return authenticationResult;
        }
    }
}
