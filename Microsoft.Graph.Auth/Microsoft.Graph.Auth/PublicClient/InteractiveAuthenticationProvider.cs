// ------------------------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All Rights Reserved.  Licensed under the MIT License.  See License in the project root for license information.
// ------------------------------------------------------------------------------

namespace Microsoft.Graph.Auth
{
    using System;
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
    public partial class InteractiveAuthenticationProvider : MsalAuthenticationBase, IAuthenticationProvider
    {
        /// <summary>
        /// A UIBehavior property
        /// </summary>
        public UIBehavior UIBehavior { get; set; }

        /// <summary>
        /// A UIParent property
        /// </summary>
        public UIParent UIParent { get; set; }
        private InteractiveFlowType InteractiveFlowType;
        private IAccount Account;
        private string LoginHint;

        // LoginHint
        /// <summary>
        /// Constructs a new <see cref="InteractiveAuthenticationProvider"/>
        /// </summary>
        /// <param name="publicClientApplication">A <see cref="PublicClientApplication"/> to pass to <see cref="DeviceCodeProvider"/> for authentication</param>
        /// <param name="scopes">Scopes required to access a protected API</param>
        /// <param name="loginHint">Identifier of the user. Generally in UserPrincipalName (UPN) format, e.g. <c>john.doe@contoso.com</c></param>
        /// <param name="uiBehavior">Designed interactive experience for the user. Defaults to <see cref="UIBehavior.SelectAccount"/></param>
        /// <param name="uiParent">Object containing a reference to the parent window/activity. REQUIRED for Xamarin.Android only.</param>
        public InteractiveAuthenticationProvider(
            IPublicClientApplication publicClientApplication,
            string[] scopes,
            string loginHint = null,
            UIBehavior? uiBehavior = null,
            UIParent uiParent = null)
            : base(scopes)
        {
            ClientApplication = publicClientApplication;
            InteractiveFlowType = InteractiveFlowType.LoginHint;
            UIBehavior = uiBehavior ?? UIBehavior.SelectAccount;
            LoginHint = loginHint;
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
        /// <param name="uiParent">Object containing a reference to the parent window/activity. REQUIRED for Xamarin.Android only.</param>
        public InteractiveAuthenticationProvider(
            IPublicClientApplication publicClientApplication,
            string[] scopes,
            IAccount account,
            UIBehavior? uiBehavior = null,
            UIParent uiParent = null)
            : base(scopes)
        {
            ClientApplication = publicClientApplication;
            InteractiveFlowType = InteractiveFlowType.Account;
            Account = account;
            UIBehavior = uiBehavior ?? UIBehavior.SelectAccount;
            UIParent = uiParent;
        }

        /// <summary>
        /// Adds an authentication header to the incoming request by checking the application's <see cref="TokenCache"/>
        /// for an unexpired access token. If a token is not found or expired, it gets a new one.
        /// </summary>
        /// <param name="httpRequestMessage">A <see cref="HttpRequestMessage"/> to authenticate</param>
        public async Task AuthenticateRequestAsync(HttpRequestMessage httpRequestMessage)
        {
            //TODO: Get ForceRefresh via RequestContext
            //TODO: Get Scopes via RequestContext
            bool forceRefresh = false;
            AuthenticationResult authenticationResult = await this.GetAccessTokenSilentAsync(Scopes, forceRefresh);

            if (authenticationResult == null)
            {
                authenticationResult = await GetNewAccessTokenAsync();
            }

            httpRequestMessage.Headers.Authorization = new AuthenticationHeaderValue(CoreConstants.Headers.Bearer, authenticationResult.AccessToken);
        }

        private async Task<AuthenticationResult> GetNewAccessTokenAsync()
        {
            IPublicClientApplication publicClientApplication = (ClientApplication as IPublicClientApplication);
            AuthenticationResult authenticationResult = null;
            
            int retryCount = 0;
            string extraQueryParameter = null;
            do
            {
                try
                {
                    if (InteractiveFlowType == InteractiveFlowType.LoginHint)
                        authenticationResult = await publicClientApplication.AcquireTokenAsync(Scopes, LoginHint, UIBehavior, extraQueryParameter, null, ClientApplication.Authority, UIParent);
                    else if (InteractiveFlowType == InteractiveFlowType.Account)
                        authenticationResult = await publicClientApplication.AcquireTokenAsync(Scopes, Account, UIBehavior, extraQueryParameter, null, ClientApplication.Authority, UIParent);
                    break;
                }
                catch (MsalServiceException serviceException)
                {
                    if (serviceException.ErrorCode == MsalAuthErrorConstants.Codes.TemporarilyUnavailable)
                    {
                        TimeSpan delay = this.GetRetryAfter(serviceException);
                        retryCount++;
                        // pause execution
                        await Task.Delay(delay);
                    }
                    else if (serviceException.Claims != null)
                    {
                        extraQueryParameter = $"claims={serviceException.Claims}";
                        retryCount++;
                    }
                    else
                    {
                        throw serviceException;
                    }
                }

            } while (retryCount < MaxRetry);


            return authenticationResult;
        }
    }
}
