// ------------------------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All Rights Reserved.  Licensed under the MIT License.  See License in the project root for license information.
// ------------------------------------------------------------------------------

namespace Microsoft.Graph.Auth
{
    using System.Net.Http;

    internal static class HttpRequestMessageExtensions
    {
        internal static MsalAuthenticationProviderOption GetMsalAuthProviderOption(this HttpRequestMessage httpRequestMessage)
        {
            AuthenticationHandlerOption authHandlerOption = httpRequestMessage.GetMiddlewareOption<AuthenticationHandlerOption>();

            return authHandlerOption?.AuthenticationProviderOption as MsalAuthenticationProviderOption ?? new MsalAuthenticationProviderOption();
        }
    }
}