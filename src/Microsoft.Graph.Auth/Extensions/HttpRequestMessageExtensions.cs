// ------------------------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All Rights Reserved.  Licensed under the MIT License.  See License in the project root for license information.
// ------------------------------------------------------------------------------

namespace Microsoft.Graph.Auth
{
    using System.Net.Http;

    internal static class HttpRequestMessageExtensions
    {
        internal static AuthenticationProviderOption GetMsalAuthProviderOption(this HttpRequestMessage httpRequestMessage)
        {
            AuthenticationHandlerOption authHandlerOption = httpRequestMessage.GetMiddlewareOption<AuthenticationHandlerOption>();
            AuthenticationProviderOption authenticationProviderOption = authHandlerOption?.AuthenticationProviderOption as AuthenticationProviderOption ?? new AuthenticationProviderOption();

            // copy the claims and scopes information
            if (authHandlerOption?.AuthenticationProviderOption is ICaeAuthenticationProviderOption caeAuthenticationProviderOption)
            {
                authenticationProviderOption.Claims = caeAuthenticationProviderOption.Claims;
                authenticationProviderOption.Scopes = caeAuthenticationProviderOption.Scopes;
            }

            return authenticationProviderOption;
        }
    }
}