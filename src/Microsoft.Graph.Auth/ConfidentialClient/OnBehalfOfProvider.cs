// ------------------------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All Rights Reserved.  Licensed under the MIT License.  See License in the project root for license information.
// ------------------------------------------------------------------------------

namespace Microsoft.Graph.Auth
{
    using System;
    using System.Linq;
    using System.Net.Http;
    using System.Net.Http.Headers;
    using System.Threading.Tasks;
    using Microsoft.Graph.Auth.Helpers;
    using Microsoft.Identity.Client;

    /// <summary>
    /// An <see cref="IAuthenticationProvider"/> implementation using MSAL.Net to acquire token by on behalf of flow.
    /// </summary>
    public class OnBehalfOfProvider : MsalAuthenticationBase, IAuthenticationProvider
    {
        /// <summary>
        /// Constructs a new <see cref="OnBehalfOfProvider"/>
        /// </summary>
        /// <param name="confidentialClientApplication">A <see cref="IConfidentialClientApplication"/> to pass to <see cref="OnBehalfOfProvider"/> for authentication.</param>
        /// <param name="scopes">Scopes required to access Microsoft graph.</param>
        public OnBehalfOfProvider(
            IConfidentialClientApplication confidentialClientApplication,
            string[] scopes)
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
        /// <param name="clientCredential">A <see cref="Microsoft.Identity.Client.ClientCredential"/> created either from an application secret or a certificate.</param>
        /// <param name="tokenStorageProvider">A <see cref="ITokenStorageProvider"/> for storing and retrieving access token.</param>
        /// <param name="tenant">Tenant to sign-in users. This defaults to <c>common</c> if non is specified.</param>
        /// <param name="nationalCloud">A <see cref="NationalCloud"/> which identifies the national cloud endpoint to use as the authority. This defaults to the global cloud <see cref="NationalCloud.Global"/> (https://login.microsoftonline.com).</param>
        /// <returns>A <see cref="IConfidentialClientApplication"/></returns>
        public static IConfidentialClientApplication CreateClientApplication(string clientId,
            string redirectUri,
            ClientCredential clientCredential,
            ITokenStorageProvider tokenStorageProvider = null,
            string tenant = null,
            NationalCloud nationalCloud = NationalCloud.Global)
        {
            TokenCacheProvider tokenCacheProvider = new TokenCacheProvider(tokenStorageProvider);
            string authority = NationalCloudHelpers.GetAuthority(nationalCloud, tenant ?? AuthConstants.Tenants.Common);
            return new ConfidentialClientApplication(clientId, authority, redirectUri, clientCredential, tokenCacheProvider.GetTokenCacheInstnce(), null);
        }

        /// <summary>
        /// Adds an authentication header to the incoming request by checking the application's <see cref="TokenCache"/>
        /// for an unexpired access token. If a token is not found or expired, it gets a new one.
        /// </summary>
        /// <param name="httpRequestMessage">A <see cref="HttpRequestMessage"/> to authenticate.</param>
        public async Task AuthenticateRequestAsync(HttpRequestMessage httpRequestMessage)
        {
            MsalAuthenticationProviderOption msalAuthProviderOption = httpRequestMessage.GetMsalAuthProviderOption();
            msalAuthProviderOption.UserAccount = GetGraphUserAccount(msalAuthProviderOption.UserAssertion?.Assertion);

            AuthenticationResult authenticationResult = await GetAccessTokenSilentAsync(msalAuthProviderOption);
            if (authenticationResult == null)
                authenticationResult = await GetNewAccessTokenAsync(msalAuthProviderOption);

            if(!string.IsNullOrEmpty(authenticationResult.AccessToken))
                httpRequestMessage.Headers.Authorization = new AuthenticationHeaderValue(CoreConstants.Headers.Bearer, authenticationResult.AccessToken);
        }

        private async Task<AuthenticationResult> GetNewAccessTokenAsync(MsalAuthenticationProviderOption msalAuthProviderOption)
        {
            AuthenticationResult authenticationResult = null;
            int retryCount = 0;
            do
            {
                try
                {
                    authenticationResult = await (ClientApplication as IConfidentialClientApplication).AcquireTokenOnBehalfOfAsync(msalAuthProviderOption.Scopes ?? Scopes, msalAuthProviderOption.UserAssertion, ClientApplication.Authority);
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

        /// <summary>
        /// Creats a <see cref="GraphUserAccount"/> object from a JWT access token.
        /// </summary>
        /// <param name="jwtAccessToken">JWT token to parse.</param>
        /// <returns></returns>
        private GraphUserAccount GetGraphUserAccount(string jwtAccessToken)
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
                TenantId = jwtPayload.Oid.ToString()
            };
        }
    }
}
