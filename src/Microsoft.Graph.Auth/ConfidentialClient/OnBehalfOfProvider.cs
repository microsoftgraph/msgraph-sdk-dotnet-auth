// ------------------------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All Rights Reserved.  Licensed under the MIT License.  See License in the project root for license information.
// ------------------------------------------------------------------------------

namespace Microsoft.Graph.Auth
{
    using Microsoft.Graph.Auth.Extensions;
    using Microsoft.Graph.Auth.Helpers;
    using Microsoft.Identity.Client;
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Net.Http;
    using System.Net.Http.Headers;
    using System.Threading.Tasks;

    /// <summary>
    /// An <see cref="IAuthenticationProvider"/> implementation using MSAL.Net to acquire token by on behalf of flow.
    /// </summary>
    public class OnBehalfOfProvider : IAuthenticationProvider
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
        /// Constructs a new <see cref="OnBehalfOfProvider"/>
        /// </summary>
        /// <param name="confidentialClientApplication">A <see cref="IConfidentialClientApplication"/> to pass to <see cref="OnBehalfOfProvider"/> for authentication.</param>
        /// <param name="scopes">Scopes required to access Microsoft Graph. This defaults to https://graph.microsoft.com/.default when none is set.</param>
        public OnBehalfOfProvider(IConfidentialClientApplication confidentialClientApplication, IEnumerable<string> scopes = null)
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
                        Message = string.Format(ErrorConstants.Message.NullValue, "confidentialClientApplication")
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
            msalAuthProviderOption.UserAccount = GetGraphUserAccountFromJwt(msalAuthProviderOption.UserAssertion?.Assertion);
            msalAuthProviderOption.Scopes = msalAuthProviderOption.Scopes ?? Scopes.ToArray();

            AuthenticationResult authenticationResult = await ClientApplication.GetAccessTokenSilentAsync(msalAuthProviderOption);
            if (authenticationResult == null)
            {
                authenticationResult = await GetNewAccessTokenAsync(msalAuthProviderOption);
            }

            if (!string.IsNullOrEmpty(authenticationResult.AccessToken))
            {
                httpRequestMessage.Headers.Authorization = new AuthenticationHeaderValue(CoreConstants.Headers.Bearer, authenticationResult.AccessToken);
            }
        }

        /// <summary>
        /// Creats a <see cref="GraphUserAccount"/> object from a JWT access token.
        /// </summary>
        /// <param name="jwtAccessToken">JWT token to parse.</param>
        /// <returns></returns>
        internal GraphUserAccount GetGraphUserAccountFromJwt(string jwtAccessToken)
        {
            if (string.IsNullOrEmpty(jwtAccessToken))
                return null;

            // Get jwt payload
            string[] jwtSegments = jwtAccessToken.Split('.');
            string payloadSegmant = jwtSegments.Count() == 1 ? jwtSegments.First() : jwtSegments[1];

            JwtPayload jwtPayload = JwtHelpers.DecodeToObject<JwtPayload>(payloadSegmant);
            return new GraphUserAccount()
            {
                Email = jwtPayload.Upn,
                ObjectId = jwtPayload.Oid.ToString(),
                TenantId = jwtPayload.Tid.ToString()
            };
        }

        private async Task<AuthenticationResult> GetNewAccessTokenAsync(AuthenticationProviderOption msalAuthProviderOption)
        {
            AuthenticationResult authenticationResult = null;
            int retryCount = 0;
            do
            {
                try
                {
                    authenticationResult = await ClientApplication.AcquireTokenOnBehalfOf(msalAuthProviderOption.Scopes, msalAuthProviderOption.UserAssertion)
                        .WithAuthority(ClientApplication.Authority)
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
