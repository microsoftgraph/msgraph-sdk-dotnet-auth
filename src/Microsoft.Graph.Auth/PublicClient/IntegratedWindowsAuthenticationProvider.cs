// ------------------------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All Rights Reserved.  Licensed under the MIT License.  See License in the project root for license information.
// ------------------------------------------------------------------------------

namespace Microsoft.Graph.Auth
{
    using Microsoft.Graph.Auth.Extensions;
    using Microsoft.Identity.Client;
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Net.Http;
    using System.Net.Http.Headers;
    using System.Threading.Tasks;

    /// <summary>
    /// An <see cref="IAuthenticationProvider"/> implementation using MSAL.Net to acquire token by integrated windows authentication.
    /// </summary>
    public class IntegratedWindowsAuthenticationProvider :IAuthenticationProvider
    {
        /// <summary>
        /// A <see cref="IPublicClientApplication"/> property.
        /// </summary>
        public IPublicClientApplication ClientApplication { get; set; }

        /// <summary>
        /// A scopes property.
        /// </summary>
        internal IEnumerable<string> Scopes { get; set; }

        /// <summary>
        /// Constructs a new <see cref="IntegratedWindowsAuthenticationProvider"/>
        /// </summary>
        /// <param name="publicClientApplication">A <see cref="IPublicClientApplication"/> to pass to <see cref="IntegratedWindowsAuthenticationProvider"/> for authentication.</param>
        /// <param name="scopes">Scopes required to access Microsoft Graph. This defaults to https://graph.microsoft.com/.default when none is set.</param>
        public IntegratedWindowsAuthenticationProvider(IPublicClientApplication publicClientApplication, IEnumerable<string> scopes = null)
        {
            Scopes = scopes ?? new List<string> { AuthConstants.DefaultScopeUrl };
            if (Scopes.Count() == 0)
            {
                throw new AuthenticationException(
                    new Error { Code = ErrorConstants.Codes.InvalidRequest, Message = ErrorConstants.Message.EmptyScopes },
                    new ArgumentException());
            }

            ClientApplication = publicClientApplication ?? throw new AuthenticationException(
                    new Error
                    {
                        Code = ErrorConstants.Codes.InvalidRequest,
                        Message = string.Format(ErrorConstants.Message.NullValue, nameof(publicClientApplication))
                    });
        }

        /// <summary>
        /// Adds an authentication header to the incoming request by checking the application's <see cref="TokenCache"/>
        /// for an unexpired access token. If a token is not found or expired, it gets a new one.
        /// </summary>
        /// <param name="httpRequestMessage">A <see cref="HttpRequestMessage"/> to authenticate.</param>
        public async Task AuthenticateRequestAsync(HttpRequestMessage httpRequestMessage)
        {
            AuthenticationProviderOption msalAuthProviderOption = httpRequestMessage.GetMsalAuthProviderOption();
            msalAuthProviderOption.Scopes = msalAuthProviderOption.Scopes ?? Scopes.ToArray();

            AuthenticationResult authenticationResult = await ClientApplication.GetAccessTokenSilentAsync(msalAuthProviderOption);

            if (authenticationResult == null)
            {
                authenticationResult = await GetNewAccessTokenAsync(msalAuthProviderOption);
            }

            if (!string.IsNullOrEmpty(authenticationResult.AccessToken))
                httpRequestMessage.Headers.Authorization = new AuthenticationHeaderValue(CoreConstants.Headers.Bearer, authenticationResult.AccessToken);
        }

        private async Task<AuthenticationResult> GetNewAccessTokenAsync(AuthenticationProviderOption msalAuthProviderOption)
        {
            AuthenticationResult authenticationResult = null;
            int retryCount = 0;
            do
            {
                try
                {
                    if (!string.IsNullOrEmpty(msalAuthProviderOption.UserAccount?.Email))
                        authenticationResult = await ClientApplication.AcquireTokenByIntegratedWindowsAuth(msalAuthProviderOption.Scopes)
                                .WithUsername(msalAuthProviderOption.UserAccount.Email)
                                .ExecuteAsync();
                    else
                        authenticationResult = await ClientApplication.AcquireTokenByIntegratedWindowsAuth(Scopes)
                                .ExecuteAsync();
                    break;
                }
                catch (MsalServiceException serviceException)
                {
                    if (serviceException.ErrorCode == ErrorConstants.Codes.TemporarilyUnavailable)
                    {
                        TimeSpan delay = this.GetRetryAfter(serviceException);
                        retryCount++;
                        // pause execution
                        await Task.Delay(delay);
                    }
                    else
                    {
                        throw new AuthenticationException(
                            new Error
                            {
                                Code = ErrorConstants.Codes.GeneralException,
                                Message = ErrorConstants.Message.UnexpectedMsalException
                            },
                            serviceException);
                    }
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

            } while (retryCount < msalAuthProviderOption.MaxRetry);

            return authenticationResult;
        }
    }
}
