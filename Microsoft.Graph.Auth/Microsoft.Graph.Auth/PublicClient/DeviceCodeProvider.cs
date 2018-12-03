// ------------------------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All Rights Reserved.  Licensed under the MIT License.  See License in the project root for license information.
// ------------------------------------------------------------------------------

namespace Microsoft.Graph.Auth
{
    using System;
    using System.Net.Http;
    using System.Threading;
    using System.Threading.Tasks;
    using Microsoft.Identity.Client;
    // Only works for tenanted or work & school accounts
    public class DeviceCodeProvider : MsalAuthenticationBase, IAuthenticationProvider
    {
        private Func<DeviceCodeResult, Task> DeviceCodeResultCallback;
        private string ExtraQueryParameters;
        private CancellationToken CancellationToken;

        public DeviceCodeProvider(
            PublicClientApplication publicClientApplication,
            string[] scopes,
            Func<DeviceCodeResult, Task> deviceCodeResultCallback,
            string extraQueryParameters = null,
            CancellationToken? cancellationToken = null)
            : base(scopes)
        {
            ClientApplication = publicClientApplication;
            DeviceCodeResultCallback = deviceCodeResultCallback;
            ExtraQueryParameters = extraQueryParameters == null ? string.Empty : extraQueryParameters;
            CancellationToken = cancellationToken == null ? CancellationToken.None : (CancellationToken)cancellationToken;
        }

        public DeviceCodeProvider(
            string clientId,
            string authority,
            string[] scopes,
            Func<DeviceCodeResult, Task> deviceCodeResultCallback,
            string extraQueryParameters = null,
            CancellationToken? cancellationToken = null)
            : base(scopes)
        {
            ClientApplication = new PublicClientApplication(clientId, authority);
            DeviceCodeResultCallback = deviceCodeResultCallback;
            ExtraQueryParameters = extraQueryParameters ?? string.Empty;
            CancellationToken = cancellationToken == null ? CancellationToken.None : (CancellationToken)cancellationToken;
        }

        public DeviceCodeProvider(
            string clientId,
            string authority,
            TokenCache userTokenCache,
            string[] scopes,
            Func<DeviceCodeResult, Task> deviceCodeResultCallback,
            string extraQueryParameters = null,
            CancellationToken? cancellationToken = null)
            : base(scopes)
        {
            ClientApplication = new PublicClientApplication(clientId, authority, userTokenCache);
            DeviceCodeResultCallback = deviceCodeResultCallback;
            ExtraQueryParameters = extraQueryParameters ?? string.Empty;
            CancellationToken = cancellationToken == null ? CancellationToken.None : (CancellationToken)cancellationToken;
        }

        internal override async Task<AuthenticationResult> GetNewAccessTokenAsync()
        {
            IPublicClientApplication publicClientApplication = (IPublicClientApplication)ClientApplication;
            AuthenticationResult authResult = await publicClientApplication.AcquireTokenWithDeviceCodeAsync(
                Scopes,
                ExtraQueryParameters,
                DeviceCodeResultCallback,
                CancellationToken);

            return authResult;
        }

        public async Task AuthenticateRequestAsync(HttpRequestMessage request)
        {
            await AddTokenToRequestAsync(request);
        }
    }
}
