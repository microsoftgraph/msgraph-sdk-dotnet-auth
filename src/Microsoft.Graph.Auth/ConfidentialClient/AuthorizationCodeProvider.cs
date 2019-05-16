// ------------------------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All Rights Reserved.  Licensed under the MIT License.  See License in the project root for license information.
// ------------------------------------------------------------------------------

namespace Microsoft.Graph.Auth
{
    using Microsoft.Identity.Client;
    using System.Collections.Generic;
    using System.Net.Http;
    using System.Net.Http.Headers;
    using System.Security.Cryptography.X509Certificates;
    using System.Threading.Tasks;

    /// <summary>
    /// An <see cref="IAuthenticationProvider"/> implementation using MSAL.Net to acquire token by authorization code flow for web apps.
    /// </summary>
    public class AuthorizationCodeProvider : MsalAuthenticationBase<IConfidentialClientApplication>, IAuthenticationProvider
    {
        /// <summary>
        /// Construct a new <see cref="AuthorizationCodeProvider"/>
        /// </summary>
        /// <param name="confidentialClientApplication"><see cref="IConfidentialClientApplication"/> used to authentication requests.</param>
        /// <param name="scopes">Scopes required to access Microsoft Graph. This defaults to https://graph.microsoft.com/.default if none is set.</param>
        public AuthorizationCodeProvider(
            IConfidentialClientApplication confidentialClientApplication,
            IEnumerable<string> scopes = null)
            : base(scopes)
        {
            ClientApplication = confidentialClientApplication ?? throw new AuthenticationException(
                    new Error
                    {
                        Code = ErrorConstants.Codes.InvalidRequest,
                        Message = string.Format(ErrorConstants.Message.NullValue, nameof(confidentialClientApplication))
                    });
        }

        /// <summary>
        /// Creates a new <see cref="IConfidentialClientApplication"/>.
        /// </summary>
        /// <param name="clientId">Client ID (also known as <i>Application ID</i>) of the application as registered in the application registration portal (https://aka.ms/msal-net-register-app).</param>
        /// <param name="redirectUri">Also named <i>Reply URI</i>, the redirect URI is the URI where the STS (Security Token Service) will call back the application
        ///  with the security token. For details see https://aka.ms/msal-net-client-applications.</param>
        /// <param name="clientCertificate">A <see cref="System.Security.Cryptography.X509Certificates.X509Certificate2"/> certificate.</param>
        /// <param name="tenant">Tenant to sign-in users. This defaults to <see cref="AadAuthorityAudience.AzureAdMultipleOrgs" /> if none is specified.</param>
        /// <param name="cloud">A <see cref="AzureCloudInstance"/> which identifies the cloud endpoint to use as the authority. This defaults to the public cloud <see cref="AzureCloudInstance.AzurePublic"/> (https://login.microsoftonline.com).</param>
        /// <returns>A <see cref="IConfidentialClientApplication"/></returns>
        /// <exception cref="AuthenticationException"></exception>
        public static IConfidentialClientApplication CreateClientApplication(
            string clientId,
            string redirectUri,
            X509Certificate2 clientCertificate,
            string tenant = null,
            AzureCloudInstance cloud = AzureCloudInstance.AzurePublic)
        {
            return CreateConfidentialClientApplicationBuilder(clientId, redirectUri, tenant, cloud)
                .WithCertificate(clientCertificate)
                .Build();
        }

        /// <summary>
        /// Creates a new <see cref="IConfidentialClientApplication"/>.
        /// </summary>
        /// <param name="clientId">Client ID (also known as <i>Application ID</i>) of the application as registered in the application registration portal (https://aka.ms/msal-net-register-app).</param>
        /// <param name="redirectUri">Also named <i>Reply URI</i>, the redirect URI is the URI where the STS (Security Token Service) will call back the application
        ///  with the security token. For details see https://aka.ms/msal-net-client-applications.</param>
        /// <param name="clientSecret">A client secret.</param>
        /// <param name="tenant">Tenant to sign-in users. This defaults to <see cref="AadAuthorityAudience.AzureAdMultipleOrgs" /> if none is specified.</param>
        /// <param name="cloud">A <see cref="AzureCloudInstance"/> which identifies the cloud endpoint to use as the authority. This defaults to the public cloud <see cref="AzureCloudInstance.AzurePublic"/> (https://login.microsoftonline.com).</param>
        /// <returns>A <see cref="IConfidentialClientApplication"/></returns>
        /// <exception cref="AuthenticationException"></exception>
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
                    new Error {
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
        /// for an unexpired access token.
        /// If an access token doesn't exist, it will throw a <see cref="AuthenticationException"/>
        /// and the web app must handle this and perform a challange.
        /// </summary>
        /// <param name="httpRequestMessage">A <see cref="HttpRequestMessage"/> to authenticate.</param>
        public async Task AuthenticateRequestAsync(HttpRequestMessage httpRequestMessage)
        {
            MsalAuthenticationProviderOption msalAuthProviderOption = httpRequestMessage.GetMsalAuthProviderOption();
            AuthenticationResult authenticationResult = await GetAccessTokenSilentAsync(msalAuthProviderOption);

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
        public async Task<AuthenticationResult> GetTokenByAuthorizationCodeAsync(string authorizationCode)
        {
            return await ClientApplication.AcquireTokenByAuthorizationCode(Scopes, authorizationCode)
                .ExecuteAsync();
        }
    }
}
