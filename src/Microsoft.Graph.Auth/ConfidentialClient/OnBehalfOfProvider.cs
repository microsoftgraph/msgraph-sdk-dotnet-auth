// ------------------------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All Rights Reserved.  Licensed under the MIT License.  See License in the project root for license information.
// ------------------------------------------------------------------------------

namespace Microsoft.Graph.Auth
{
    using Microsoft.Graph.Auth.Helpers;
    using Microsoft.Identity.Client;
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Net.Http;
    using System.Net.Http.Headers;
    using System.Security.Cryptography.X509Certificates;
    using System.Threading.Tasks;

    /// <summary>
    /// An <see cref="IAuthenticationProvider"/> implementation using MSAL.Net to acquire token by on behalf of flow.
    /// </summary>
    public class OnBehalfOfProvider : MsalAuthenticationBase<IConfidentialClientApplication>, IAuthenticationProvider
    {
        /// <summary>
        /// Constructs a new <see cref="OnBehalfOfProvider"/>
        /// </summary>
        /// <param name="confidentialClientApplication">A <see cref="IConfidentialClientApplication"/> to pass to <see cref="OnBehalfOfProvider"/> for authentication.</param>
        /// <param name="scopes">Scopes required to access Microsoft Graph. This defaults to https://graph.microsoft.com/.default when none is set.</param>
        public OnBehalfOfProvider(
            IConfidentialClientApplication confidentialClientApplication,
            IEnumerable<string> scopes = null)
            : base(scopes)
        {
            ClientApplication = confidentialClientApplication ?? throw new AuthenticationException(
                    new Error
                    {
                        Code = ErrorConstants.Codes.InvalidRequest,
                        Message = string.Format(ErrorConstants.Message.NullValue, "confidentialClientApplication")
                    });
        }

        /// <summary>
        /// Creates a new <see cref="IConfidentialClientApplication"/>
        /// </summary>
        /// <param name="clientId">Client ID (also known as <i>Application ID</i>) of the application as registered in the application registration portal (https://aka.ms/msal-net-register-app).</param>
        /// <param name="redirectUri">also named <i>Reply URI</i>, the redirect URI is the URI where the STS (Security Token Service) will call back the application
        ///  with the security token. For details see https://aka.ms/msal-net-client-applications.</param>
        /// <param name="clientSecret">A client secret.</param>
        /// <param name="tenant">Tenant to sign-in users. This defaults to <see cref="AadAuthorityAudience.AzureAdMultipleOrgs" /> if none is specified.</param>
        /// <param name="cloud">A <see cref="AzureCloudInstance"/> which identifies the cloud endpoint to use as the authority. This defaults to the public cloud <see cref="AzureCloudInstance.AzurePublic"/> (https://login.microsoftonline.com).</param>
        /// <returns>A <see cref="IConfidentialClientApplication"/></returns>
        /// <exception cref="AuthenticationException"/>
        public static IConfidentialClientApplication CreateClientApplication(
            string clientId,
            string redirectUri,
            string clientSecret,
            string tenant = null,
            AzureCloudInstance cloud = AzureCloudInstance.AzurePublic)
        {
            return CreateConfidentialClientApplicationBuilder(clientId, redirectUri, tenant, cloud)
                .WithClientSecret(clientSecret)
                .Build();
        }

        private static ConfidentialClientApplicationBuilder CreateConfidentialClientApplicationBuilder(
            string clientId,
            string redirectUri, 
            string tenant,
            AzureCloudInstance cloud)
        {
            if (string.IsNullOrEmpty(clientId))
                throw new AuthenticationException(
                    new Error
                    {
                        Code = ErrorConstants.Codes.InvalidRequest,
                        Message = string.Format(ErrorConstants.Message.NullValue, nameof(clientId))
                    });

            if (string.IsNullOrEmpty(redirectUri))
                throw new AuthenticationException(
                    new Error
                    {
                        Code = ErrorConstants.Codes.InvalidRequest,
                        Message = string.Format(ErrorConstants.Message.NullValue, nameof(redirectUri))
                    });


            var builder = ConfidentialClientApplicationBuilder
                .Create(clientId)
                .WithRedirectUri(redirectUri);

            if (tenant != null)
                builder = builder.WithAuthority(cloud, tenant);
            else
                builder = builder.WithAuthority(cloud, AadAuthorityAudience.AzureAdMultipleOrgs);

            return builder;
        }

        /// <summary>
        /// Adds an authentication header to the incoming request by checking the application's <see cref="TokenCache"/>
        /// for an unexpired access token. If a token is not found or expired, it gets a new one.
        /// </summary>
        /// <param name="httpRequestMessage">A <see cref="HttpRequestMessage"/> to authenticate.</param>
        public async Task AuthenticateRequestAsync(HttpRequestMessage httpRequestMessage)
        {
            MsalAuthenticationProviderOption msalAuthProviderOption = httpRequestMessage.GetMsalAuthProviderOption();
            msalAuthProviderOption.UserAccount = GetGraphUserAccountFromJwt(msalAuthProviderOption.UserAssertion?.Assertion);

            AuthenticationResult authenticationResult = await GetAccessTokenSilentAsync(msalAuthProviderOption);
            if (authenticationResult == null)
                authenticationResult = await GetNewAccessTokenAsync(msalAuthProviderOption);

            if(!string.IsNullOrEmpty(authenticationResult.AccessToken))
                httpRequestMessage.Headers.Authorization = new AuthenticationHeaderValue(CoreConstants.Headers.Bearer, authenticationResult.AccessToken);
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

        private async Task<AuthenticationResult> GetNewAccessTokenAsync(MsalAuthenticationProviderOption msalAuthProviderOption)
        {
            AuthenticationResult authenticationResult = null;
            int retryCount = 0;
            do
            {
                try
                {
                    authenticationResult = await ClientApplication.AcquireTokenOnBehalfOf(msalAuthProviderOption.Scopes ?? Scopes, msalAuthProviderOption.UserAssertion)
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

            } while (retryCount < MaxRetry);

            return authenticationResult;
        }
    }
}
