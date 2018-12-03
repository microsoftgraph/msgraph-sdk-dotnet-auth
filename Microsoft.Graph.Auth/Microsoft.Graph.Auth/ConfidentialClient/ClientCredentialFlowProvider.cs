// ------------------------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All Rights Reserved.  Licensed under the MIT License.  See License in the project root for license information.
//

namespace Microsoft.Graph.Auth
{
    using Microsoft.Identity.Client;
    using System.Net.Http;
    using System.Threading.Tasks;

    public class ClientCredentialFlowProvider : MsalAuthenticationBase, IAuthenticationProvider
    {
        private readonly string ResourceUrl;
        private readonly bool ForceRefresh;

        public ClientCredentialFlowProvider(
            ConfidentialClientApplication confidentialClientApplication,
            string resourceUrl,
            bool forceRefresh = false)
            : base(null)
        {
            ClientApplication = confidentialClientApplication;
            ResourceUrl = resourceUrl;
            ForceRefresh = forceRefresh;
        }

        public ClientCredentialFlowProvider(
            string clientId,
            string redirectUri,
            ClientCredential clientCredential,
            TokenCache appTokenCache,
            string resourceUrl,
            bool forceRefresh = false)
            : base(null)
        {
            ClientApplication = new ConfidentialClientApplication(clientId, redirectUri, clientCredential, null, appTokenCache);
            ResourceUrl = resourceUrl;
            ForceRefresh = forceRefresh;
        }

        public ClientCredentialFlowProvider(
            string clientId,
            string authority,
            string redirectUri,
            ClientCredential clientCredential,
            TokenCache appTokenCache,
            string resourceUrl,
            bool forceRefresh = false)
            : base(null)
        {
            ClientApplication = new ConfidentialClientApplication(clientId, authority, redirectUri, clientCredential, null, appTokenCache);
            ResourceUrl = resourceUrl;
            ForceRefresh = forceRefresh;
        }

        public async Task AuthenticateRequestAsync(HttpRequestMessage request)
        {
            // AcquireTokenForClientAsync will check the token, no need to call AcquireTokenSilentAsync 
            await AddTokenToRequestAsync(request, true);
        }

        internal override async Task<AuthenticationResult> GetNewAccessTokenAsync()
        {
            AuthenticationResult authResult = null;
            IConfidentialClientApplication confidentialClientApplication = (IConfidentialClientApplication)ClientApplication;
            if (ForceRefresh)
                authResult = await confidentialClientApplication.AcquireTokenForClientAsync(new string[] { ResourceUrl + "/.default" }, ForceRefresh);
            else
                authResult = await confidentialClientApplication.AcquireTokenForClientAsync(new string[] { ResourceUrl + "/.default" });

            return authResult;
        }
    }
}
