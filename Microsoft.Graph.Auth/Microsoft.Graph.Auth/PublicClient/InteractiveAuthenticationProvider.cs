// ------------------------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All Rights Reserved.  Licensed under the MIT License.  See License in the project root for license information.
// ------------------------------------------------------------------------------

namespace Microsoft.Graph.Auth
{
    using System.Net.Http;
    using System.Net.Http.Headers;
    using System.Threading.Tasks;
    using Microsoft.Identity.Client;
    internal enum InteractiveFlowType
    {
        LoginHint,
        Account
    }

    /// <summary>
    /// An <see cref="IAuthenticationProvider"/> implementation using MSAL.Net to acquire token interactively
    /// </summary>
    public class InteractiveAuthenticationProvider : MsalAuthenticationBase, IAuthenticationProvider
    {
        private InteractiveFlowType InteractiveFlowType;
        private IAccount Account;
        private UIBehavior UIBehavior;
        private string LoginHint;
        private string[] ExtraScopesToConsent;
        private UIParent UIParent;

        // LoginHint
        /// <summary>
        /// Constructs a new <see cref="InteractiveAuthenticationProvider"/>
        /// </summary>
        /// <param name="publicClientApplication">A <see cref="PublicClientApplication"/> to pass to <see cref="DeviceCodeProvider"/> for authentication</param>
        /// <param name="scopes">Scopes required to access a protected API</param>
        /// <param name="loginHint">Identifier of the user. Generally in UserPrincipalName (UPN) format, e.g. <c>john.doe@contoso.com</c></param>
        /// <param name="uiBehavior">Designed interactive experience for the user. Defaults to <see cref="UIBehavior.SelectAccount"/></param>
        /// <param name="extraScopesToConsent">scopes that you can request the end user to consent upfront, in addition to the scopes for the protected Web API
        /// for which you want to acquire a security token.</param>
        /// <param name="uiParent">Object containing a reference to the parent window/activity. REQUIRED for Xamarin.Android only.</param>
        public InteractiveAuthenticationProvider(
            PublicClientApplication publicClientApplication,
            string[] scopes,
            string loginHint = null,
            UIBehavior? uiBehavior = null,
            string[] extraScopesToConsent = null,
            UIParent uiParent = null)
            : base(scopes, publicClientApplication.ClientId)
        {
            ClientApplication = publicClientApplication;
            InteractiveFlowType = InteractiveFlowType.LoginHint;
            UIBehavior = (uiBehavior == null) ? UIBehavior.SelectAccount : (UIBehavior)uiBehavior;
            LoginHint = loginHint;
            ExtraScopesToConsent = extraScopesToConsent;
            UIParent = uiParent;
        }

        /// <summary>
        /// Constructs a new <see cref="InteractiveAuthenticationProvider"/>
        /// </summary>
        /// <param name="clientId">Client ID (also known as <i>Application ID</i>) of the application as registered in the application registration portal (https://aka.ms/msal-net-register-app)</param>
        /// <param name="scopes">Scopes required to access a protected API</param>
        /// <param name="loginHint">Identifier of the user. Generally in UserPrincipalName (UPN) format, e.g. <c>john.doe@contoso.com</c></param>
        /// <param name="uiBehavior">Designed interactive experience for the user. Defaults to <see cref="UIBehavior.SelectAccount"/></param>
        /// <param name="extraScopesToConsent">scopes that you can request the end user to consent upfront, in addition to the scopes for the protected Web API
        /// for which you want to acquire a security token.</param>
        /// <param name="uiParent">Object containing a reference to the parent window/activity. REQUIRED for Xamarin.Android only.</param>
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
        public InteractiveAuthenticationProvider(
            string clientId,
            string[] scopes,
            string loginHint = null,
            UIBehavior? uiBehavior = null,
            string[] extraScopesToConsent = null,
            UIParent uiParent = null,
            NationalCloud nationalCloud = NationalCloud.Global,
            string tenant = null)
            : base(scopes, clientId)
        {
            string authority = this.GetAuthority(nationalCloud, tenant ?? AuthConstants.Tenants.Common);
            ClientApplication = new PublicClientApplication(clientId, authority);
            InteractiveFlowType = InteractiveFlowType.LoginHint;
            UIBehavior = (uiBehavior == null) ? UIBehavior.SelectAccount : (UIBehavior)uiBehavior;
            LoginHint = loginHint;
            ExtraScopesToConsent = extraScopesToConsent;
            UIParent = uiParent;
        }

        /// <summary>
        /// Constructs a new <see cref="InteractiveAuthenticationProvider"/>
        /// </summary>
        /// <param name="clientId">Client ID (also known as <i>Application ID</i>) of the application as registered in the application registration portal (https://aka.ms/msal-net-register-app)</param>
        /// <param name="userTokenCacheProvider">A <see cref="ITokenCacheProvider"/> for storing access tokens.</param>
        /// <param name="scopes">Scopes required to access a protected API</param>
        /// <param name="loginHint">Identifier of the user. Generally in UserPrincipalName (UPN) format, e.g. <c>john.doe@contoso.com</c></param>
        /// <param name="uiBehavior">Designed interactive experience for the user. Defaults to <see cref="UIBehavior.SelectAccount"/></param>
        /// <param name="extraScopesToConsent">scopes that you can request the end user to consent upfront, in addition to the scopes for the protected Web API
        /// for which you want to acquire a security token.</param>
        /// <param name="uiParent">Object containing a reference to the parent window/activity. REQUIRED for Xamarin.Android only.</param>
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
        public InteractiveAuthenticationProvider(
            string clientId,
            ITokenCacheProvider userTokenCacheProvider,
            string[] scopes,
            string loginHint = null,
            UIBehavior? uiBehavior = null,
            string[] extraScopesToConsent = null,
            UIParent uiParent = null,
            NationalCloud nationalCloud = NationalCloud.Global,
            string tenant = null)
            : base(scopes, clientId)
        {
            string authority = this.GetAuthority(nationalCloud, tenant ?? AuthConstants.Tenants.Common);
            ClientApplication = new PublicClientApplication(clientId, authority, userTokenCacheProvider.GetTokenCacheInstance());
            InteractiveFlowType = InteractiveFlowType.LoginHint;
            UIBehavior = (uiBehavior == null) ? UIBehavior.SelectAccount : (UIBehavior)uiBehavior;
            LoginHint = loginHint;
            ExtraScopesToConsent = extraScopesToConsent;
            UIParent = uiParent;
        }

        // User
        /// <summary>
        /// Constructs a new <see cref="InteractiveAuthenticationProvider"/>
        /// </summary>
        /// <param name="publicClientApplication">A <see cref="PublicClientApplication"/> to pass to <see cref="DeviceCodeProvider"/> for authentication</param>
        /// <param name="scopes">Scopes required to access a protected API</param>
        /// <param name="account">Account to use for the interactive token acquisition. See <see cref="IAccount"/> for ways to get an account</param>
        /// <param name="uiBehavior">Designed interactive experience for the user. Defaults to <see cref="UIBehavior.SelectAccount"/></param>
        /// <param name="extraScopesToConsent">scopes that you can request the end user to consent upfront, in addition to the scopes for the protected Web API
        /// for which you want to acquire a security token.</param>
        /// <param name="uiParent">Object containing a reference to the parent window/activity. REQUIRED for Xamarin.Android only.</param>
        public InteractiveAuthenticationProvider(
            PublicClientApplication publicClientApplication,
            string[] scopes,
            IAccount account,
            UIBehavior? uiBehavior = null,
            string[] extraScopesToConsent = null,
            UIParent uiParent = null)
            : base(scopes, publicClientApplication.ClientId)
        {
            ClientApplication = publicClientApplication;
            InteractiveFlowType = InteractiveFlowType.Account;
            Account = account;
            UIBehavior = (uiBehavior == null) ? UIBehavior.SelectAccount : (UIBehavior)uiBehavior;
            ExtraScopesToConsent = extraScopesToConsent;
            UIParent = uiParent;
        }

        /// <summary>
        /// Constructs a new <see cref="InteractiveAuthenticationProvider"/>
        /// </summary>
        /// <param name="clientId">Client ID (also known as <i>Application ID</i>) of the application as registered in the application registration portal (https://aka.ms/msal-net-register-app)</param>
        /// <param name="scopes">Scopes required to access a protected API</param>
        /// <param name="account">Account to use for the interactive token acquisition. See <see cref="IAccount"/> for ways to get an account</param>
        /// <param name="uiBehavior">Designed interactive experience for the user. Defaults to <see cref="UIBehavior.SelectAccount"/></param>
        /// <param name="extraScopesToConsent">scopes that you can request the end user to consent upfront, in addition to the scopes for the protected Web API
        /// for which you want to acquire a security token.</param>
        /// <param name="uiParent">Object containing a reference to the parent window/activity. REQUIRED for Xamarin.Android only.</param>
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
        public InteractiveAuthenticationProvider(
            string clientId,
            string[] scopes,
            IAccount account,
            UIBehavior? uiBehavior = null,
            string[] extraScopesToConsent = null,
            UIParent uiParent = null,
            NationalCloud nationalCloud = NationalCloud.Global,
            string tenant = null)
            : base(scopes, clientId)
        {
            string authority = this.GetAuthority(nationalCloud, tenant ?? AuthConstants.Tenants.Common);
            ClientApplication = new PublicClientApplication(clientId, authority);
            InteractiveFlowType = InteractiveFlowType.Account;
            Account = account;
            UIBehavior = (uiBehavior == null) ? UIBehavior.SelectAccount : (UIBehavior)uiBehavior;
            ExtraScopesToConsent = extraScopesToConsent;
            UIParent = uiParent;
        }

        /// <summary>
        /// Constructs a new <see cref="InteractiveAuthenticationProvider"/>
        /// </summary>
        /// <param name="clientId">Client ID (also known as <i>Application ID</i>) of the application as registered in the application registration portal (https://aka.ms/msal-net-register-app)</param>
        /// <param name="scopes">Scopes required to access a protected API</param>
        /// <param name="account">Account to use for the interactive token acquisition. See <see cref="IAccount"/> for ways to get an account</param>
        /// <param name="userTokenCacheProvider">A <see cref="ITokenCacheProvider"/> for storing access tokens.</param>
        /// <param name="uiBehavior">Designed interactive experience for the user. Defaults to <see cref="UIBehavior.SelectAccount"/></param>
        /// <param name="extraScopesToConsent">scopes that you can request the end user to consent upfront, in addition to the scopes for the protected Web API
        /// for which you want to acquire a security token.</param>
        /// <param name="uiParent">Object containing a reference to the parent window/activity. REQUIRED for Xamarin.Android only.</param>
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
        public InteractiveAuthenticationProvider(
            string clientId,
            string[] scopes,
            IAccount account,
            ITokenCacheProvider userTokenCacheProvider,
            UIBehavior? uiBehavior = null,
            string[] extraScopesToConsent = null,
            UIParent uiParent = null,
            NationalCloud nationalCloud = NationalCloud.Global,
            string tenant = null)
            : base(scopes, clientId)
        {
            string authority = this.GetAuthority(nationalCloud, tenant ?? AuthConstants.Tenants.Common);
            ClientApplication = new PublicClientApplication(clientId, authority, userTokenCacheProvider.GetTokenCacheInstance());
            InteractiveFlowType = InteractiveFlowType.Account;
            Account = account;
            UIBehavior = (uiBehavior == null) ? UIBehavior.SelectAccount : (UIBehavior)uiBehavior;
            ExtraScopesToConsent = extraScopesToConsent;
            UIParent = uiParent;
        }

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

                if (InteractiveFlowType == InteractiveFlowType.LoginHint)
                    authenticationResult = await publicClientApplication.AcquireTokenAsync(Scopes, LoginHint, UIBehavior, null, ExtraScopesToConsent, ClientApplication.Authority, UIParent);
                else if (InteractiveFlowType == InteractiveFlowType.Account)
                    authenticationResult = await publicClientApplication.AcquireTokenAsync(Scopes, Account, UIBehavior, null, ExtraScopesToConsent, ClientApplication.Authority, UIParent);
            }

            httpRequestMessage.Headers.Authorization = new AuthenticationHeaderValue(CoreConstants.Headers.Bearer, authenticationResult.AccessToken);
        }
    }
}
