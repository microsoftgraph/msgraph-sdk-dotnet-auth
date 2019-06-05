// ------------------------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All Rights Reserved.  Licensed under the MIT License.  See License in the project root for license information.
// ------------------------------------------------------------------------------

namespace Microsoft.Graph.Auth
{
    using Microsoft.Identity.Client;
    using System.Security;

    /// <summary>
    /// Options class used to configure the authentication providers.
    /// </summary>
    public class AuthenticationProviderOption : IAuthenticationProviderOption
    {
        /// <summary>
        /// A MaxRetry property.
        /// </summary>
        internal int MaxRetry { get; set; } = 1;

        /// <summary>
        /// Scopes to use when authenticating.
        /// </summary>
        public string[] Scopes { get ; set ; }

        /// <summary>
        /// Whether or not to force a token refresh.
        /// </summary>
        public bool ForceRefresh { get; set; }

        /// <summary>
        /// Graph user account to use when authenticating.
        /// </summary>
        public GraphUserAccount UserAccount { get; set; }

        /// <summary>
        /// An single claim asserted by a JWT token.
        /// </summary>
        public UserAssertion UserAssertion { get; set; }

        /// <summary>
        /// Password to use when authenticating with UsernamePasswordProvider.
        /// </summary>
        public SecureString Password { get; set; }
    }
}