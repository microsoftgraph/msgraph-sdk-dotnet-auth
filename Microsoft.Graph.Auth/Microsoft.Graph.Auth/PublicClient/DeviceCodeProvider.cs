// ------------------------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All Rights Reserved.  Licensed under the MIT License.  See License in the project root for license information.
// ------------------------------------------------------------------------------

namespace Microsoft.Graph.Auth
{
    using System;
    using System.Net.Http;
    using System.Net.Http.Headers;
    using System.Threading;
    using System.Threading.Tasks;
    using Microsoft.Identity.Client;
    // Only works for tenanted or work & school accounts
    /// <summary>
    /// An <see cref="IAuthenticationProvider"/> implementation using MSAL.Net to acquire token by device code.
    /// </summary>
    public class DeviceCodeProvider : MsalAuthenticationBase, IAuthenticationProvider
    {
        private Func<DeviceCodeResult, Task> DeviceCodeResultCallback;

        /// <summary>
        /// Constructs a new <see cref="DeviceCodeProvider"/>
        /// </summary>
        /// <param name="publicClientApplication">A <see cref="PublicClientApplication"/> to pass to <see cref="DeviceCodeProvider"/> for authentication</param>
        /// <param name="scopes">Scopes required to access a protected API</param>
        /// <param name="deviceCodeResultCallback">Callback containing information to show the user about how to authenticate and enter the device code.</param>
        public DeviceCodeProvider(
            IPublicClientApplication publicClientApplication,
            string[] scopes,
            Func<DeviceCodeResult, Task> deviceCodeResultCallback)
            : base(scopes)
        {
            ClientApplication = publicClientApplication;
            DeviceCodeResultCallback = deviceCodeResultCallback;
        }

        /// <summary>
        /// Adds an authentication header to the incoming request by checking the application's <see cref="TokenCache"/>
        /// for an unexpired access token. If a token is not found or expired, it gets a new one.
        /// </summary>
        /// <param name="httpRequestMessage">A <see cref="HttpRequestMessage"/> to authenticate</param>
        public async Task AuthenticateRequestAsync(HttpRequestMessage httpRequestMessage)
        {
            //TODO: Get CancellationToken via parameter
            //TODO: Get ForceRefresh via RequestContext
            //TODO: Get Scopes via RequestContext
            CancellationToken cancellationToken = CancellationToken.None;
            bool forceRefresh = false;
            AuthenticationResult authenticationResult = await this.GetAccessTokenSilentAsync(Scopes, forceRefresh);

            if (authenticationResult == null)
            {
                authenticationResult = await GetNewAccessTokenAsync(cancellationToken);
            }

            httpRequestMessage.Headers.Authorization = new AuthenticationHeaderValue(CoreConstants.Headers.Bearer, authenticationResult.AccessToken);
        }

        private async Task<AuthenticationResult> GetNewAccessTokenAsync(CancellationToken cancellationToken)
        {
            AuthenticationResult authenticationResult = null;
            int retryCount = 0;
            string extraQueryParameter = null;
            do
            {
                try
                {
                    authenticationResult = await (ClientApplication as IPublicClientApplication).AcquireTokenWithDeviceCodeAsync(
                        Scopes,
                        extraQueryParameter,
                        DeviceCodeResultCallback,
                        cancellationToken);
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
