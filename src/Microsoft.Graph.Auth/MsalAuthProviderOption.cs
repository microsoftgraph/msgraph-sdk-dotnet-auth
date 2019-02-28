// ------------------------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All Rights Reserved.  Licensed under the MIT License.  See License in the project root for license information.
// ------------------------------------------------------------------------------

namespace Microsoft.Graph.Auth
{
    using Microsoft.Identity.Client;

    public class MsalAuthProviderOption : IAuthenticationProviderOption
    {
        public string[] Scopes { get ; set ; }
        public bool ForceRefresh { get; set; }
        public GraphUserAccount UserAccount { get; set; }
        public UserAssertion UserAssertion { get; set; }
        public string Password { get; set; }
    }
}
