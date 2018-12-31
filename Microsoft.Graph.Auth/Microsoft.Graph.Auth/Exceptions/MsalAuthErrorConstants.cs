// ------------------------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All Rights Reserved.  Licensed under the MIT License.  See License in the project root for license information.
// ------------------------------------------------------------------------------

namespace Microsoft.Graph.Auth
{
    internal static class MsalAuthErrorConstants
    {
        internal static class Codes
        {
            internal const string AuthenticationChallengeRequired = "AuthenticationChallengeRequired";
            internal const string TemporarilyUnavailable = "temporarily_unavailable";
        }

        internal static class Message
        {
            internal const string AuthenticationChallengeRequired = "Authentication Challange is required";
            internal const string MissingRetryAfterHeader = "Missing retry after header";
        }
    }
}
