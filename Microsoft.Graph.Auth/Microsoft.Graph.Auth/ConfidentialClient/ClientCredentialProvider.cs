// ------------------------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All Rights Reserved.  Licensed under the MIT License.  See License in the project root for license information.
//

namespace Microsoft.Graph.Auth
{
    using Microsoft.Identity.Client;
    using System;
    using System.Net.Http;
    using System.Net.Http.Headers;
    using System.Threading.Tasks;

    /// <summary>
    /// An <see cref="IAuthenticationProvider"/> implementation using MSAL.Net to acquire token by client credential flow.
    /// </summary>
    public class ClientCredentialProvider : MsalAuthenticationBase, IAuthenticationProvider
    {
        private readonly string ResourceUrl = "https://graph.microsoft.com/.default";
        internal bool ForceRefresh { get; }

        /// <summary>
        /// Constructs a new <see cref=" ClientCredentialProvider"/>
        /// </summary>
        /// <param name="confidentialClientApplication">A <see cref="ConfidentialClientApplication"/> to pass to <see cref="ClientCredentialProvider"/> for authentication</param>
        public ClientCredentialProvider(
            ConfidentialClientApplication confidentialClientApplication)
            : base(null, confidentialClientApplication.ClientId)
        {
            ClientApplication = confidentialClientApplication;
        }

        /// <summary>
        /// Constructs a new <see cref="ClientCredentialProvider"/>
        /// </summary>
        /// <param name="clientId">Client ID (also known as <i>Application ID</i>) of the application as registered in the application registration portal (https://aka.ms/msal-net-register-app)</param>
        /// <param name="redirectUri">also named <i>Reply URI</i>, the redirect URI is the URI where the STS (Security Token Service) will call back the application
        ///  with the security token. For details see https://aka.ms/msal-net-client-applications </param>
        /// <param name="clientCredential">A <see cref="Microsoft.Identity.Client.ClientCredential"/> created either from an application secret or a certificate</param>
        /// <param name="appTokenCacheProvider">A <see cref="ITokenCacheProvider"/> for storing access tokens.</param>
        /// <param name="nationalCloud">A <see cref="NationalCloud"/> which identifies the national cloud endpoint to use as the authority. This defaults to the global cloud <see cref="NationalCloud.Global"/> (https://login.microsoftonline.com) </param>
        /// <param name="tenant">Tenant to sign-in users.
        /// Usual tenants are :
        /// <list type="bullet">
        /// <item><description>Tenant ID of the Azure AD tenant or a domain associated with Azure AD tenant, to sign-in users of a specific organization only;</description></item>
        /// <item><description><c>common</c>, to sign-in users with any work and school accounts or Microsoft personal accounts;</description></item>
        /// <item><description><c>organizations</c>, to sign-in users with any work and school accounts;</description></item>
        /// <item><description><c>consumers</c>, to sign-in users with only personal Microsoft accounts(live);</description></item>
        /// </list>
        /// This defaults to <c>common</c>
        /// </param>
        public ClientCredentialProvider(
            string clientId,
            string redirectUri,
            ClientCredential clientCredential,
            ITokenCacheProvider appTokenCacheProvider,
            NationalCloud nationalCloud = NationalCloud.Global,
            string tenant = null)
            : base(null, clientId)
        {
            string authority = this.GetAuthority(nationalCloud, tenant ?? AuthConstants.Tenants.Common);
            ClientApplication = new ConfidentialClientApplication(clientId, authority, redirectUri, clientCredential, null, appTokenCacheProvider.GetTokenCacheInstance());
        }

        /// <summary>
        /// Adds an authentication header to the incoming request by checking the application's <see cref="TokenCache"/>
        /// for an unexpired access token. If a token is not found or expired, it gets a new one.
        /// </summary>
        /// <param name="httpRequestMessage">A <see cref="HttpRequestMessage"/> to authenticate</param>
        public async Task AuthenticateRequestAsync(HttpRequestMessage httpRequestMessage)
        {
            int retryCount = 0;
            do
            {
                try
                {
                    AuthenticationResult authenticationResult = await GetNewAccessTokenAsync(httpRequestMessage);
                    httpRequestMessage.Headers.Authorization = new AuthenticationHeaderValue(CoreConstants.Headers.Bearer, authenticationResult.AccessToken);
                    break;
                }
                catch (MsalServiceException serviceException)
                {
                    if (serviceException.ErrorCode == MsalAuthErrorConstants.Codes.TemporarilyUnavailable)
                    {
                        TimeSpan delay = GetRetryAfter(serviceException);
                        retryCount++;
                        // pause execution
                        await Task.Delay(delay);
                    }
                    else
                    {
                        throw serviceException;
                    }
                }
            } while (retryCount < MaxRetry);
        }

        private async Task<AuthenticationResult> GetNewAccessTokenAsync(HttpRequestMessage httpRequestMessage)
        {
            AuthenticationResult authenticationResult = null;
            IConfidentialClientApplication confidentialClientApplication = (IConfidentialClientApplication)ClientApplication;
            //TODO: Get forceRefresh via RequestContext
            if (ForceRefresh)
                authenticationResult = await confidentialClientApplication.AcquireTokenForClientAsync(new string[] { ResourceUrl }, ForceRefresh);
            else
                authenticationResult = await confidentialClientApplication.AcquireTokenForClientAsync(new string[] { ResourceUrl });

            return authenticationResult;
        }
    }
}
