using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Identity.Client;

namespace Microsoft.Graph.Auth
{
    public class DeviceCodeFlowProvider : MsalAuthenticationBase, IAuthenticationProvider
    {
        private Func<DeviceCodeResult, Task> _deviceCodeResultCallback;
        private CancellationToken _cancellationToken;

        public DeviceCodeFlowProvider(PublicClientApplication clientApplication, string[] scopes, Func<DeviceCodeResult, Task> deviceCodeResultCallback)
            : base(clientApplication, scopes)
        {
            _deviceCodeResultCallback = deviceCodeResultCallback;
        }

        public DeviceCodeFlowProvider(PublicClientApplication clientApplication, string[] scopes, Func<DeviceCodeResult, Task> deviceCodeResultCallback,
            CancellationToken cancellationToken)
            : base(clientApplication, scopes)
        {
            _deviceCodeResultCallback = deviceCodeResultCallback;
            _cancellationToken = cancellationToken;
        }

        internal override async Task<string> GetNewAccessTokenAsync()
        {
            AuthenticationResult authResult;
            PublicClientApplication publicClientApplication = ClientApplication as PublicClientApplication;

            if (_cancellationToken != null)
                authResult = await publicClientApplication.AcquireTokenWithDeviceCodeAsync(Scopes, _deviceCodeResultCallback, _cancellationToken);
            else
                authResult = await publicClientApplication.AcquireTokenWithDeviceCodeAsync(Scopes, _deviceCodeResultCallback);

            return authResult.AccessToken;
        }

        public async Task AuthenticateRequestAsync(HttpRequestMessage request)
        {
            await AddTokenToRequestAsync(request);
        }
    }
}
