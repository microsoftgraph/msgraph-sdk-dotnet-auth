// ------------------------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All Rights Reserved.  Licensed under the MIT License.  See License in the project root for license information.
// ------------------------------------------------------------------------------

namespace Microsoft.Graph.Auth
{
    using Microsoft.Identity.Client;
    public static class ConfidentialClientApplicationExtension
    {
        /// <summary>
        /// Creates a new <see cref="ConfidentialClientApplication"/>
        /// </summary>
        /// <param name="clientId">Client ID (also known as <i>Application ID</i>) of the application as registered in the application registration portal (https://aka.ms/msal-net-register-app)</param>
        /// <param name="redirectUri">also named <i>Reply URI</i>, the redirect URI is the URI where the STS (Security Token Service) will call back the application
        ///  with the security token. For details see https://aka.ms/msal-net-client-applications </param>
        /// <param name="clientCredential">A <see cref="Microsoft.Identity.Client.ClientCredential"/> created either from an application secret or a certificate</param>
        /// <param name="userTokenCache">A <see cref="TokenCache"/> for storing access tokens.</param>
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
        public static ConfidentialClientApplication CreateClientApplication(this AuthorizationCodeProvider authProvider,
            string clientId,
            string redirectUri,
            ClientCredential clientCredential,
            TokenCache userTokenCache = null,
            NationalCloud nationalCloud = NationalCloud.Global,
            string tenant = null)
        {
            string authority = authProvider.GetAuthority(nationalCloud, tenant ?? AuthConstants.Tenants.Common);
            return new ConfidentialClientApplication(clientId, authority, redirectUri, clientCredential, userTokenCache ?? new TokenCache(), null);
        }

        /// <summary>
        /// Creates a new <see cref="ConfidentialClientApplication"/>
        /// </summary>
        /// <param name="clientId">Client ID (also known as <i>Application ID</i>) of the application as registered in the application registration portal (https://aka.ms/msal-net-register-app)</param>
        /// <param name="clientCredential">A <see cref="Microsoft.Identity.Client.ClientCredential"/> created either from an application secret or a certificate</param>
        /// <param name="appTokenCache">A <see cref="TokenCache"/> for storing access tokens.</param>
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
        public static ConfidentialClientApplication CreateClientApplication(this ClientCredentialProvider authProvider,
            string clientId,
            ClientCredential clientCredential,
            TokenCache appTokenCache = null,
            NationalCloud nationalCloud = NationalCloud.Global,
            string tenant = null)
        {
            string authority = authProvider.GetAuthority(nationalCloud, tenant ?? AuthConstants.Tenants.Common);
            return new ConfidentialClientApplication(clientId, authority, string.Empty, clientCredential, null, appTokenCache ?? new TokenCache());
        }

        /// <summary>
        /// Creates a new <see cref="ConfidentialClientApplication"/>
        /// </summary>
        /// <param name="clientId">Client ID (also known as <i>Application ID</i>) of the application as registered in the application registration portal (https://aka.ms/msal-net-register-app)</param>
        /// <param name="redirectUri">also named <i>Reply URI</i>, the redirect URI is the URI where the STS (Security Token Service) will call back the application
        ///  with the security token. For details see https://aka.ms/msal-net-client-applications </param>
        /// <param name="clientCredential">A <see cref="Microsoft.Identity.Client.ClientCredential"/> created either from an application secret or a certificate</param>
        /// <param name="userTokenCache">A <see cref="TokenCache"/> for storing access tokens.</param>
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
        public static ConfidentialClientApplication CreateClientApplication(this OnBehalfOfProvider authProvider,
            string clientId,
            string redirectUri,
            ClientCredential clientCredential,
            TokenCache userTokenCache = null,
            NationalCloud nationalCloud = NationalCloud.Global,
            string tenant = null)
        {
            string authority = authProvider.GetAuthority(nationalCloud, tenant ?? AuthConstants.Tenants.Common);
            return new ConfidentialClientApplication(clientId, authority, redirectUri, clientCredential, userTokenCache ?? new TokenCache(), null);
        }
    }
}
