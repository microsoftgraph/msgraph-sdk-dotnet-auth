// ------------------------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All Rights Reserved.  Licensed under the MIT License.  See License in the project root for license information.
// ------------------------------------------------------------------------------

namespace Microsoft.Graph.Auth
{
    using System.Net.Http;
    using System.Threading.Tasks;
    using Microsoft.Identity.Client;
    internal enum InteractiveFlowType
    {
        LoginHint,
        Account
    }
    public class InteractiveFlowProvider : MsalAuthenticationBase, IAuthenticationProvider
    {
        private InteractiveFlowType InteractiveFlowType;
        private IAccount Account;
        private UIBehavior UIBehavior;
        private string LoginHint;
        private string ExtraQueryParameters;
        private string[] ExtraScopesToConsent;
        private UIParent UIParent;

        // LoginHint
        public InteractiveFlowProvider(
            PublicClientApplication publicClientApplication,
            string[] scopes,
            string loginHint = null,
            UIBehavior? uiBehavior = null,
            string extraQueryParameters = null,
            string[] extraScopesToConsent = null,
            UIParent uiParent = null)
            : base(scopes)
        {
            ClientApplication = publicClientApplication;
            InteractiveFlowType = InteractiveFlowType.LoginHint;
            UIBehavior = (uiBehavior == null) ? UIBehavior.SelectAccount : (UIBehavior)uiBehavior;
            LoginHint = loginHint;
            ExtraQueryParameters = extraQueryParameters;
            ExtraScopesToConsent = extraScopesToConsent;
            UIParent = uiParent;
        }

        public InteractiveFlowProvider(
            string clientId,
            string[] scopes,
            string loginHint = null,
            UIBehavior? uiBehavior = null,
            string extraQueryParameters = null,
            string[] extraScopesToConsent = null,
            UIParent uiParent = null)
            : base(scopes)
        {
            ClientApplication = new PublicClientApplication(clientId);
            InteractiveFlowType = InteractiveFlowType.LoginHint;
            UIBehavior = (uiBehavior == null) ? UIBehavior.SelectAccount : (UIBehavior)uiBehavior;
            LoginHint = loginHint;
            ExtraQueryParameters = extraQueryParameters;
            ExtraScopesToConsent = extraScopesToConsent;
            UIParent = uiParent;
        }

        public InteractiveFlowProvider(
            string clientId,
            string authority,
            string[] scopes,
            string loginHint = null,
            UIBehavior? uiBehavior = null,
            string extraQueryParameters = null,
            string[] extraScopesToConsent = null,
            UIParent uiParent = null)
            : base(scopes)
        {
            ClientApplication = new PublicClientApplication(clientId, authority);
            InteractiveFlowType = InteractiveFlowType.LoginHint;
            UIBehavior = (uiBehavior == null) ? UIBehavior.SelectAccount : (UIBehavior)uiBehavior;
            LoginHint = loginHint;
            ExtraQueryParameters = extraQueryParameters;
            ExtraScopesToConsent = extraScopesToConsent;
            UIParent = uiParent;
        }

        public InteractiveFlowProvider(
            string clientId,
            string authority,
            TokenCache userTokenCache,
            string[] scopes,
            string loginHint = null,
            UIBehavior? uiBehavior = null,
            string extraQueryParameters = null,
            string[] extraScopesToConsent = null,
            UIParent uiParent = null)
            : base(scopes)
        {
            ClientApplication = new PublicClientApplication(clientId, authority, userTokenCache);
            InteractiveFlowType = InteractiveFlowType.LoginHint;
            UIBehavior = (uiBehavior == null) ? UIBehavior.SelectAccount : (UIBehavior)uiBehavior;
            LoginHint = loginHint;
            ExtraQueryParameters = extraQueryParameters;
            ExtraScopesToConsent = extraScopesToConsent;
            UIParent = uiParent;
        }

        // User
        public InteractiveFlowProvider(
            PublicClientApplication publicClientApplication,
            string[] scopes,
            IAccount account,
            UIBehavior? uiBehavior = null,
            string extraQueryParameters = null,
            string[] extraScopesToConsent = null,
            UIParent uiParent = null)
            : base(scopes)
        {
            ClientApplication = publicClientApplication;
            InteractiveFlowType = InteractiveFlowType.Account;
            Account = account;
            UIBehavior = (uiBehavior == null) ? UIBehavior.SelectAccount : (UIBehavior)uiBehavior;
            ExtraQueryParameters = extraQueryParameters;
            ExtraScopesToConsent = extraScopesToConsent;
            UIParent = uiParent;
        }

        public InteractiveFlowProvider(
            string clientId,
            string[] scopes,
            IAccount account,
            UIBehavior? uiBehavior = null,
            string extraQueryParameters = null,
            string[] extraScopesToConsent = null,
            string authority = null,
            UIParent uiParent = null)
            : base(scopes)
        {
            ClientApplication = new PublicClientApplication(clientId);
            InteractiveFlowType = InteractiveFlowType.Account;
            Account = account;
            UIBehavior = (uiBehavior == null) ? UIBehavior.SelectAccount : (UIBehavior)uiBehavior;
            ExtraQueryParameters = extraQueryParameters;
            ExtraScopesToConsent = extraScopesToConsent;
            UIParent = uiParent;
        }

        public InteractiveFlowProvider(
            string clientId,
            string[] scopes,
            IAccount account,
            string authority,
            UIBehavior? uiBehavior = null,
            string extraQueryParameters = null,
            string[] extraScopesToConsent = null,
            UIParent uiParent = null)
            : base(scopes)
        {
            ClientApplication = new PublicClientApplication(clientId, authority);
            InteractiveFlowType = InteractiveFlowType.Account;
            Account = account;
            UIBehavior = (uiBehavior == null) ? UIBehavior.SelectAccount : (UIBehavior)uiBehavior;
            ExtraQueryParameters = extraQueryParameters;
            ExtraScopesToConsent = extraScopesToConsent;
            UIParent = uiParent;
        }

        public InteractiveFlowProvider(
            string clientId,
            string[] scopes,
            IAccount account,
            string authority,
            TokenCache userTokenCache,
            UIBehavior? uiBehavior = null,
            string extraQueryParameters = null,
            string[] extraScopesToConsent = null,
            UIParent uiParent = null)
            : base(scopes)
        {
            ClientApplication = new PublicClientApplication(clientId, authority, userTokenCache);
            InteractiveFlowType = InteractiveFlowType.Account;
            Account = account;
            UIBehavior = (uiBehavior == null) ? UIBehavior.SelectAccount : (UIBehavior)uiBehavior;
            ExtraQueryParameters = extraQueryParameters;
            ExtraScopesToConsent = extraScopesToConsent;
            UIParent = uiParent;
        }

        public async Task AuthenticateRequestAsync(HttpRequestMessage request)
        {
            await AddTokenToRequestAsync(request);
        }

        internal override async Task<AuthenticationResult> GetNewAccessTokenAsync()
        {
            AuthenticationResult authResult = null;
            var publicClientApplication = (IPublicClientApplication)ClientApplication;

            if (InteractiveFlowType == InteractiveFlowType.LoginHint)
                authResult = await publicClientApplication.AcquireTokenAsync(Scopes, LoginHint, UIBehavior, ExtraQueryParameters, ExtraScopesToConsent, ClientApplication.Authority, UIParent);
            else if (InteractiveFlowType == InteractiveFlowType.Account)
                authResult = await publicClientApplication.AcquireTokenAsync(Scopes, Account, UIBehavior, ExtraQueryParameters, ExtraScopesToConsent, ClientApplication.Authority, UIParent);

            return authResult;
        }
    }
}
