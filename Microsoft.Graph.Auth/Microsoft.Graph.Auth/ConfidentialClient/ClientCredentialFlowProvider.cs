using Microsoft.Identity.Client;
using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;

namespace Microsoft.Graph.Auth
{
    public class ClientCredentialFlowProvider: MsalAuthenticationBase, IAuthenticationProvider
    {
        private bool _forceRefresh;
        private string _resourceUrl;

        public ClientCredentialFlowProvider(ConfidentialClientApplication confidentialClientApplication, string resourceUrl)
            :base(confidentialClientApplication, null)
        {
            _resourceUrl = resourceUrl;
        }

        public ClientCredentialFlowProvider(ConfidentialClientApplication confidentialClientApplication, string resourceUrl, bool forceRefresh)
            : base(confidentialClientApplication, null)
        {
            _forceRefresh = forceRefresh;
            _resourceUrl = resourceUrl;
        }

        internal override async Task<string> GetNewAccessTokenAsync()
        {
            AuthenticationResult authResult = null;
            if (_forceRefresh)
                authResult = await (ClientApplication as ConfidentialClientApplication).AcquireTokenForClientAsync(new string[] { _resourceUrl + "/.default" }, _forceRefresh);
            else
                authResult = await (ClientApplication as ConfidentialClientApplication).AcquireTokenForClientAsync(new string[] { _resourceUrl + "/.default" });

            return authResult.AccessToken;
        }

        public async Task AuthenticateRequestAsync(HttpRequestMessage request)
        {
            await AddTokenToRequestAsync(request);
        }
    }
}
