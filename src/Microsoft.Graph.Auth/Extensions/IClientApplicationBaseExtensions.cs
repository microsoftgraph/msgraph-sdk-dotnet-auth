// ------------------------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All Rights Reserved.  Licensed under the MIT License.  See License in the project root for license information.
// ------------------------------------------------------------------------------

using System;
using System.Linq;
using System.Threading.Tasks;
using System.Collections.Generic;
using Microsoft.Identity.Client;

namespace Microsoft.Graph.Auth.Extensions
{
    /// <summary>
    /// Conatins extension methods for <see cref="IClientApplicationBase"/>.
    /// </summary>
    public static class IClientApplicationBaseExtensions
    {
        /// <summary>
        /// Attempts to acquire access token silently from the token cache.
        /// </summary>
        /// <exception cref="AuthenticationException">An exception occured when attempting to get access token silently.</exception>
        internal static async Task<AuthenticationResult> GetAccessTokenSilentAsync(this IClientApplicationBase clientApplication, AuthenticationProviderOption msalAuthProviderOption)
        {
            IAccount account;
            if (msalAuthProviderOption.UserAccount?.ObjectId != null)
            {
                // Parse GraphUserAccount to IAccount instance
                account = new GraphAccount(msalAuthProviderOption.UserAccount);
            }
            else
            {
                // If no graph user account is passed, try get the one in cache.
                IEnumerable<IAccount> accounts = await clientApplication.GetAccountsAsync();
                account = accounts.FirstOrDefault();
            }

            if (account == null)
            {
                return null;
            }

            try
            {
                return await clientApplication.AcquireTokenSilent(msalAuthProviderOption.Scopes, account)
                        .WithAuthority(clientApplication.Authority)
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
