using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Identity.Client;

namespace Microsoft.Graph.Auth
{
    public class BehalfOfFlowProvider : MsalAuthenticationBase, IAuthenticationProvider
    {
        private UserAssertion _userAssertion;
        private string _authority;

        public BehalfOfFlowProvider(ConfidentialClientApplication confidentialClientApplication, string[] scopes, UserAssertion userAssertion)
            : base(confidentialClientApplication, scopes)
        {
            _userAssertion = userAssertion;
        }

        public BehalfOfFlowProvider(ConfidentialClientApplication confidentialClientApplication, string[] scopes, UserAssertion userAssertion, string authority)
            : base(confidentialClientApplication, scopes)
        {
            _userAssertion = userAssertion;
            _authority = authority;
        }

        internal override async Task<string> GetNewAccessTokenAsync()
        {
            AuthenticationResult authResult = null;
            if (_authority != null)
                authResult = await (ClientApplication as ConfidentialClientApplication).AcquireTokenOnBehalfOfAsync(Scopes, _userAssertion);
            else
                authResult = await (ClientApplication as ConfidentialClientApplication).AcquireTokenOnBehalfOfAsync(Scopes, _userAssertion, _authority);

            return authResult.AccessToken;
        }

        public async Task AuthenticateRequestAsync(HttpRequestMessage request)
        {
            await AddTokenToRequestAsync(request);
        }
    }
}
