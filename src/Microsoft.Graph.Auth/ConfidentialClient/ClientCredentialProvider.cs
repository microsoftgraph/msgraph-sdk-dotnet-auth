// ------------------------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All Rights Reserved.  Licensed under the MIT License.  See License in the project root for license information.
// ------------------------------------------------------------------------------

namespace Microsoft.Graph.Auth
{
    using Microsoft.Identity.Client;
    using System;
    using System.Net.Http;
    using System.Net.Http.Headers;
    using System.Security.Cryptography.X509Certificates;
    using System.Threading.Tasks;

    /// <summary>
    /// An <see cref="IAuthenticationProvider"/> implementation using MSAL.Net to acquire token by client credential flow.
    /// </summary>
    public class ClientCredentialProvider : MsalAuthenticationBase<IConfidentialClientApplication>, IAuthenticationProvider
    {
        /// <summary>
        /// Constructs a new <see cref=" ClientCredentialProvider"/>
        /// </summary>
        /// <param name="confidentialClientApplication">A <see cref="IConfidentialClientApplication"/> to pass to <see cref="ClientCredentialProvider"/> for authentication.</param>
        public ClientCredentialProvider(
            IConfidentialClientApplication confidentialClientApplication)
            : base(null)
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
        /// <param name="clientId">Client ID (also known as <i>Application ID</i>) of the application as registered in the application registration portal (https://aka.ms/msal-net-register-app)</param>
        /// <param name="clientCertificate">A <see cref="System.Security.Cryptography.X509Certificates.X509Certificate2"/> certificate.</param>
        /// <param name="tenant">Tenant to sign-in users. This defaults to <see cref="AadAuthorityAudience.AzureAdMultipleOrgs" /> if none is specified.</param>
        /// <param name="cloud">A <see cref="AzureCloudInstance"/> which identifies the cloud endpoint to use as the authority. This defaults to the public cloud <see cref="AzureCloudInstance.AzurePublic"/> (https://login.microsoftonline.com).</param>
        /// <returns>A <see cref="IConfidentialClientApplication"/></returns>
        /// <exception cref="AuthenticationException"/>
        public static IConfidentialClientApplication CreateClientApplication(
            string clientId,
            X509Certificate2 clientCertificate,
            string tenant = null,
            AzureCloudInstance cloud = AzureCloudInstance.AzurePublic)
        {
            return CreateConfidentialClientApplicationBuilder(clientId, tenant, cloud)
                .WithCertificate(clientCertificate)
                .Build();
        }

        /// <summary>
        /// Creates a new <see cref="IConfidentialClientApplication"/>
        /// </summary>
        /// <param name="clientId">Client ID (also known as <i>Application ID</i>) of the application as registered in the application registration portal (https://aka.ms/msal-net-register-app)</param>
        /// <param name="clientSecret">A client secret.</param>
        /// <param name="tenant">Tenant to sign-in users. This defaults to <see cref="AadAuthorityAudience.AzureAdMultipleOrgs" /> if none is specified.</param>
        /// <param name="cloud">A <see cref="AzureCloudInstance"/> which identifies the cloud endpoint to use as the authority. This defaults to the public cloud <see cref="AzureCloudInstance.AzurePublic"/> (https://login.microsoftonline.com).</param>
        /// <returns>A <see cref="IConfidentialClientApplication"/></returns>
        /// <exception cref="AuthenticationException"/>
        public static IConfidentialClientApplication CreateClientApplication(
            string clientId,
            string clientSecret,
            string tenant = null,
            AzureCloudInstance cloud = AzureCloudInstance.AzurePublic)
        {
            return CreateConfidentialClientApplicationBuilder(clientId, tenant, cloud)
                .WithClientSecret(clientSecret)
                .Build();
        }

        private static ConfidentialClientApplicationBuilder CreateConfidentialClientApplicationBuilder(
            string clientId,
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


            var builder = ConfidentialClientApplicationBuilder
                .Create(clientId)
                .WithRedirectUri("https://replyUrl");

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
        /// <param name="httpRequestMessage">A <see cref="HttpRequestMessage"/> to authenticate</param>
        public async Task AuthenticateRequestAsync(HttpRequestMessage httpRequestMessage)
        {
            MsalAuthenticationProviderOption msalAuthProviderOption = httpRequestMessage.GetMsalAuthProviderOption();
            int retryCount = 0;
            do
            {
                try
                {
                    AuthenticationResult authenticationResult = await ClientApplication.AcquireTokenForClient(new string[] { AuthConstants.DefaultScopeUrl })
                        .WithForceRefresh(msalAuthProviderOption.ForceRefresh)
                        .ExecuteAsync();

                    if (!string.IsNullOrEmpty(authenticationResult?.AccessToken))
                        httpRequestMessage.Headers.Authorization = new AuthenticationHeaderValue(CoreConstants.Headers.Bearer, authenticationResult.AccessToken);
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
                catch(Exception exception)
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
        }
    }
}
