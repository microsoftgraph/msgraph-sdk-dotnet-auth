// ------------------------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All Rights Reserved.  Licensed under the MIT License.  See License in the project root for license information.
// ------------------------------------------------------------------------------

namespace Microsoft.Graph.Auth
{
    using Microsoft.Identity.Client;
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Threading.Tasks;

    /// <summary>
    /// Abstract class containing common API methods and properties to retrieve an access token. All authentication providers extend this class
    /// </summary>
    public abstract class MsalAuthenticationBase<T> where T : IClientApplicationBase
    {
        /// <summary>
        /// A <see cref="ClientApplicationBase"/> property
        /// </summary>
        internal T ClientApplication { get; set; }

        /// <summary>
        /// A scopes property
        /// </summary>
        internal IEnumerable<string> Scopes { get; }

        /// <summary>
        /// A MaxRetry property.
        /// </summary>
        internal int MaxRetry { get; set; } = 1;

        /// <summary>
        /// Constructs a new <see cref="MsalAuthenticationBase{T}"/>
        /// </summary>
        /// <param name="graphScopes">Scopes requested to access a protected API</param>
        public MsalAuthenticationBase(IEnumerable<string> graphScopes = null)
        {
            Scopes = graphScopes ?? new List<string> { AuthConstants.DefaultScopeUrl };

            if (Scopes.Count() == 0)
            {
                throw new AuthenticationException(new Error { Code = ErrorConstants.Codes.InvalidRequest, Message = ErrorConstants.Message.EmptyScopes }, new ArgumentException());
            }
        }

        /// <summary>
        /// Attempts to acquire access token from the token cache silently by calling AcquireTokenSilentAsync
        /// </summary>
        internal async Task<AuthenticationResult> GetAccessTokenSilentAsync(MsalAuthenticationProviderOption msalAuthProviderOption)
        {
            IAccount account = null;

            if(msalAuthProviderOption.UserAccount?.ObjectId != null)
            {
                // Parse GraphUserAccount to IAccount instance
                account = new GraphAccount(msalAuthProviderOption.UserAccount);
            }
            else
            {
                // If no graph user account is passed, try get the one in cache.
                IEnumerable<IAccount> accounts = await ClientApplication.GetAccountsAsync();
                account = accounts.FirstOrDefault();
            }

            if (account == null)
                return null;

            try
            {                
                return await ClientApplication.AcquireTokenSilent(msalAuthProviderOption.Scopes ?? Scopes, account)                        
                        .WithAuthority(ClientApplication.Authority)
                        .WithForceRefresh(msalAuthProviderOption.ForceRefresh)
                        .ExecuteAsync();
            }
            catch (MsalException)
            {
                return null;
            }
            catch (Exception exception)
            {
                throw new AuthenticationException(
                        new Error
                        {
                            Code = ErrorConstants.Codes.GeneralException,
                            Message = ErrorConstants.Message.UnexpectedException
                        },
                        exception);
            }
        }
    }
}
