// ------------------------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All Rights Reserved.  Licensed under the MIT License.  See License in the project root for license information.
// ------------------------------------------------------------------------------

namespace Microsoft.Graph.Auth
{
    internal static class ErrorConstants
    {
        internal static class Codes
        {
            internal const string TemporarilyUnavailable = "temporarily_unavailable";
            internal const string AuthenticationChallengeRequired = "authenticationChallengeRequired";
            internal const string InvalidClaim = "invalidClaim";
            internal const string InvalidRequest = "invalidRequest";
            internal const string GeneralException = "generalException";
            internal const string InvalidJWT = "invalidJWT";
        }

        internal static class Message
        {
            internal const string AuthenticationChallengeRequired = "Authentication challenge is required.";
            internal const string MissingRetryAfterHeader = "Missing retry after header.";
            internal const string MissingClaim = "Missing '{0}' claim.";
            internal const string NullValue = "{0} cannot be null.";
            internal static string UnexpectedMsalException = "Unexpected exception returned from MSAL.";
            internal static string UnexpectedException = "Unexpected exception occurred while authenticating the request.";
            internal const string InvalidJWT = "Invalid JWT access token.";
            internal const string EmptyScopes = "Scopes cannot be empty.";
        }
    }
}
