// ------------------------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All Rights Reserved.  Licensed under the MIT License.  See License in the project root for license information.
// ------------------------------------------------------------------------------

using Microsoft.Graph.Auth.Extensions;
using Microsoft.Identity.Client;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading.Tasks;

namespace Microsoft.Graph.Auth
{
    /// <summary>
    /// An <see cref="IAuthenticationProvider"/> implementation using MSAL.Net to acquire token by authorization code flow for web apps.
    /// </summary>
    public class AuthorizationCodeProvider : IAuthenticationProvider
    {
        /// <summary>
        /// A <see cref="IConfidentialClientApplication"/> property.
        /// </summary>
        public IConfidentialClientApplication ClientApplication { get; set; }

        /// <summary>
        /// A scopes property.
        /// </summary>
        internal IEnumerable<string> Scopes { get; set; }

        /// <summary>
        /// Construct a new <see cref="AuthorizationCodeProvider"/>.
        /// </summary>
        /// <param name="confidentialClientApplication"><see cref="IConfidentialClientApplication"/> used to authentication requests.</param>
        /// <param name="scopes">Scopes required to access Microsoft Graph. This defaults to https://graph.microsoft.com/.default if none is set.</param>
        public AuthorizationCodeProvider(IConfidentialClientApplication confidentialClientApplication, IEnumerable<string> scopes = null)
        {
            Scopes = scopes ?? new List<string> { AuthConstants.DefaultScopeUrl };
            if (Scopes.Count() == 0)
            {
                throw new AuthenticationException(
                    new Error { Code = ErrorConstants.Codes.InvalidRequest, Message = ErrorConstants.Message.EmptyScopes },
                    new ArgumentException());
            }

            ClientApplication = confidentialClientApplication ?? throw new AuthenticationException(
                    new Error
                    {
                        Code = ErrorConstants.Codes.InvalidRequest,
                        Message = string.Format(ErrorConstants.Message.NullValue, nameof(confidentialClientApplication))
                    });
        }

        /// <summary>
        /// Adds an authentication header to the incoming request by checking the application's <see cref="TokenCache"/>
        /// for an unexpired access token.
        /// If an access token doesn't exist, it will throw a <see cref="AuthenticationException"/>
        /// and the web app must handle this and perform a challange.
        /// </summary>
        /// <param name="httpRequestMessage">A <see cref="HttpRequestMessage"/> to authenticate.</param>
        public async Task AuthenticateRequestAsync(HttpRequestMessage httpRequestMessage)
        {
            AuthenticationProviderOption msalAuthProviderOption = httpRequestMessage.GetMsalAuthProviderOption();
            msalAuthProviderOption.Scopes = msalAuthProviderOption.Scopes ?? Scopes.ToArray();

            AuthenticationResult authenticationResult = await ClientApplication.GetAccessTokenSilentAsync(msalAuthProviderOption);

            if (string.IsNullOrEmpty(authenticationResult?.AccessToken))
            {
                throw new AuthenticationException(
                    new Error
                    {
                        Code = ErrorConstants.Codes.AuthenticationChallengeRequired,
                        Message = ErrorConstants.Message.AuthenticationChallengeRequired
                    });
            }

            httpRequestMessage.Headers.Authorization = new AuthenticationHeaderValue(CoreConstants.Headers.Bearer, authenticationResult.AccessToken);
        }

        /// <summary>
        /// Helper used in Startup class to retrieve a token from an authorization code.
        /// </summary>
        /// <param name="authorizationCode">An authorization code received from an openid connect auth flow.</param>
        /// <returns></returns>
        public async Task<AuthenticationResult> GetAccessTokenByAuthorizationCode(string authorizationCode)
        {
            return await ClientApplication.AcquireTokenByAuthorizationCode(Scopes, authorizationCode).ExecuteAsync();
        }
    }
}
