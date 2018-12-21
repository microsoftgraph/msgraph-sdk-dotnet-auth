// ------------------------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All Rights Reserved.  Licensed under the MIT License.  See License in the project root for license information.
// ------------------------------------------------------------------------------

namespace Microsoft.Graph.Auth
{
    using System.Threading.Tasks;
    using Microsoft.Identity.Client;
    using System.Net.Http;
    using System.Net.Http.Headers;

#if NET45 || NET_CORE
    // Works for tenanted & work & school accounts
    // Only available on .Net & .Net core and UWP
    /// <summary>
    /// An <see cref="IAuthenticationProvider"/> implementation using MSAL.Net to acquire token by integrated windows authentication.
    /// </summary>
    public class IntegratedWindowsAuthenticationProvider : MsalAuthenticationBase, IAuthenticationProvider
    {
        private string Username;

        /// <summary>
        /// Constructs a new <see cref="IntegratedWindowsAuthenticationProvider"/>
        /// </summary>
        /// <param name="publicClientApplication">A <see cref="PublicClientApplication"/> to pass to <see cref="DeviceCodeProvider"/> for authentication</param>
        /// <param name="scopes">Scopes required to access a protected API</param>
        public IntegratedWindowsAuthenticationProvider(
           PublicClientApplication publicClientApplication,
           string[] scopes)
           : base(scopes, publicClientApplication.ClientId)
        {
            ClientApplication = publicClientApplication;
        }

        /// <summary>
        /// Constructs a new <see cref="IntegratedWindowsAuthenticationProvider"/>
        /// </summary>
        /// <param name="clientId">Client ID (also known as <i>Application ID</i>) of the application as registered in the application registration portal (https://aka.ms/msal-net-register-app)</param>
        /// <param name="scopes">Scopes required to access a protected API</param>
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
        public IntegratedWindowsAuthenticationProvider(
           string clientId,
           string[] scopes,
           NationalCloud nationalCloud = NationalCloud.Global,
           string tenant = null)
           : base(scopes, clientId)
        {
            string authority = this.GetAuthority(nationalCloud, tenant ?? AuthConstants.Tenants.Organizations);
            ClientApplication = new PublicClientApplication(clientId, authority);
        }

        /// <summary>
        /// Constructs a new <see cref="IntegratedWindowsAuthenticationProvider"/>
        /// </summary>
        /// <param name="clientId">Client ID (also known as <i>Application ID</i>) of the application as registered in the application registration portal (https://aka.ms/msal-net-register-app)</param>
        /// <param name="userTokenCacheProvider">A <see cref="ITokenCacheProvider"/> for storing access tokens.</param>
        /// <param name="scopes">Scopes required to access a protected API</param>
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
        public IntegratedWindowsAuthenticationProvider(
            string clientId,
            ITokenCacheProvider userTokenCacheProvider,
            string[] scopes,
            NationalCloud nationalCloud = NationalCloud.Global,
            string tenant = null)
            : base(scopes, clientId)
        {
            string authority = this.GetAuthority(nationalCloud, tenant ?? AuthConstants.Tenants.Organizations);
            ClientApplication = new PublicClientApplication(clientId, authority, userTokenCacheProvider.GetTokenCacheInstance());
        }

#if !NET_CORE
        /// <summary>
        /// Constructs a new <see cref="IntegratedWindowsAuthenticationProvider"/>
        /// </summary>
        /// <param name="publicClientApplication">A <see cref="PublicClientApplication"/> to pass to <see cref="DeviceCodeProvider"/> for authentication</param>
        /// <param name="scopes">Scopes required to access a protected API</param>
        /// <param name="username">Identifier of the user account for which to acquire a token with Integrated Windows authentication. 
        /// Generally in UserPrincipalName (UPN) format, e.g. john.doe@contoso.com</param>
        public IntegratedWindowsAuthenticationProvider(
           PublicClientApplication publicClientApplication,
           string[] scopes,
           string username)
           : base(scopes, publicClientApplication.ClientId)
        {
            ClientApplication = publicClientApplication;
            Username = username;
        }

        /// <summary>
        /// Constructs a new <see cref="IntegratedWindowsAuthenticationProvider"/>
        /// </summary>
        /// <param name="clientId">Client ID (also known as <i>Application ID</i>) of the application as registered in the application registration portal (https://aka.ms/msal-net-register-app)</param>
        /// <param name="scopes">Scopes required to access a protected API</param>
        /// <param name="username">Identifier of the user account for which to acquire a token with Integrated Windows authentication. 
        /// Generally in UserPrincipalName (UPN) format, e.g. john.doe@contoso.com</param>
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
        public IntegratedWindowsAuthenticationProvider(
            string clientId,
            string[] scopes, 
            string username,
            NationalCloud nationalCloud = NationalCloud.Global,
            string tenant = null)
            :base(scopes, clientId)
        {
            string authority = this.GetAuthority(nationalCloud, tenant ?? AuthConstants.Tenants.Organizations);
            ClientApplication = new PublicClientApplication(clientId, authority);
            Username = username;
        }

        /// <summary>
        /// Constructs a new <see cref="IntegratedWindowsAuthenticationProvider"/>
        /// </summary>
        /// <param name="clientId">Client ID (also known as <i>Application ID</i>) of the application as registered in the application registration portal (https://aka.ms/msal-net-register-app)</param>
        /// <param name="userTokenCacheProvider">A <see cref="ITokenCacheProvider"/> for storing access tokens.</param>
        /// <param name="scopes">Scopes required to access a protected API</param>
        /// <param name="username">Identifier of the user account for which to acquire a token with Integrated Windows authentication. 
        /// Generally in UserPrincipalName (UPN) format, e.g. john.doe@contoso.com</param>
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
        public IntegratedWindowsAuthenticationProvider(
            string clientId,
            ITokenCacheProvider userTokenCacheProvider,
            string[] scopes,
            string username,
            NationalCloud nationalCloud = NationalCloud.Global,
            string tenant = null)
            :base(scopes, clientId)
        {
            string authority = this.GetAuthority(nationalCloud, tenant ?? AuthConstants.Tenants.Organizations);
            ClientApplication = new PublicClientApplication(clientId, authority, userTokenCacheProvider.GetTokenCacheInstance());
            Username = username;
        }
#endif
        /// <summary>
        /// Adds an authentication header to the incoming request by checking the application's <see cref="TokenCache"/>
        /// for an unexpired access token. If a token is not found or expired, it gets a new one.
        /// </summary>
        /// <param name="httpRequestMessage">A <see cref="HttpRequestMessage"/> to authenticate</param>
        public async Task AuthenticateRequestAsync(HttpRequestMessage httpRequestMessage)
        {
            AuthenticationResult authenticationResult = await this.GetAccessTokenSilentAsync();

            if (authenticationResult == null)
            {
                IPublicClientApplication publicClientApplication = (IPublicClientApplication)ClientApplication;

                if (Username != null)
                    authenticationResult = await publicClientApplication.AcquireTokenByIntegratedWindowsAuthAsync(Scopes, Username);
                else
                    authenticationResult = await publicClientApplication.AcquireTokenByIntegratedWindowsAuthAsync(Scopes);
            }

            httpRequestMessage.Headers.Authorization = new AuthenticationHeaderValue(CoreConstants.Headers.Bearer, authenticationResult.AccessToken);
        }
    }
#endif
}
