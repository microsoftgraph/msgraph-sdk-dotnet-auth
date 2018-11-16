using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Identity.Client;

namespace Microsoft.Graph.Auth
{
    internal enum InteractiveFlowType
    {
       LoginHint,
       User
    }
    public class InteractiveFlowProvider : MsalAuthenticationBase, IAuthenticationProvider
    {
        private InteractiveFlowType interactiveFlowType;
        private IAccount _account;
        private UIBehavior _behavior;
        private string _loginHint;
        private string _extraQueryParameters;
        private string[] _extraScopesToConsent;
        private string _authority;
        private UIParent _parent;

        // LogiHint
        public InteractiveFlowProvider(PublicClientApplication clientApplication,
            string[] scopes,
            string loginHint = null,
            UIBehavior? behavior = null,
            string extraQueryParameters = null,
            string[] extraScopesToConsent = null,
            string authority = null,
            UIParent parent = null)
            : base(clientApplication, scopes)
        {
            interactiveFlowType = InteractiveFlowType.LoginHint;
            _behavior = (behavior == null) ? UIBehavior.SelectAccount : (UIBehavior)behavior;
            _loginHint = loginHint;
            _extraQueryParameters = extraQueryParameters;
            _extraScopesToConsent = extraScopesToConsent;
            _authority = (authority == null) ? clientApplication.Authority : authority; ;
            _parent = parent;
        }

        // User
        public InteractiveFlowProvider(
            PublicClientApplication clientApplication,
            string[] scopes,
            IAccount account,
            UIBehavior? behavior = null,
            string extraQueryParameters = null,
            string[] extraScopesToConsent = null,
            string authority = null,
            UIParent parent = null)
            :base(clientApplication, scopes)
        {
            interactiveFlowType = InteractiveFlowType.User;
            _account = account;
            _behavior = (behavior == null) ? UIBehavior.SelectAccount : (UIBehavior) behavior;
            _extraQueryParameters = extraQueryParameters;
            _extraScopesToConsent = extraScopesToConsent;
            _authority = (authority == null) ? clientApplication.Authority : authority;
            _parent = parent;
        }
        public async Task AuthenticateRequestAsync(HttpRequestMessage request)
        {
            await AddTokenToRequestAsync(request);
        }

        internal override async Task<string> GetNewAccessTokenAsync()
        {
            AuthenticationResult authResult = null;
            var publicClientApplication = ClientApplication as PublicClientApplication;

            if (interactiveFlowType == InteractiveFlowType.LoginHint)
                authResult = await publicClientApplication.AcquireTokenAsync(Scopes, _loginHint, _behavior, _extraQueryParameters, _extraScopesToConsent, _authority, _parent);
            else if (interactiveFlowType == InteractiveFlowType.User)
                authResult = await publicClientApplication.AcquireTokenAsync(Scopes, _account, _behavior, _extraQueryParameters, _extraScopesToConsent, _authority, _parent);

            return authResult.AccessToken;
        }
    }
}
