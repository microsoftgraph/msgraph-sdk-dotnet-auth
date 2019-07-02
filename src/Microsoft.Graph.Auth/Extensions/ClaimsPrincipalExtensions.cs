// ------------------------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All Rights Reserved.  Licensed under the MIT License.  See License in the project root for license information.
// ------------------------------------------------------------------------------

namespace Microsoft.Graph.Auth
{
    using System.Security.Claims;

    /// <summary>
    /// Extension methods for the <see cref="System.Security.Claims.ClaimsPrincipal"/> class.
    /// </summary>
    public static class ClaimsPrincipalExtensions
    {
        /// <summary>
        /// Converts an instance of the <see cref="System.Security.Claims.ClaimsPrincipal"/> class to an
        /// instance of the <see cref="Microsoft.Graph.GraphUserAccount"/> class.
        /// </summary>
        /// <param name="claimsPrincipal"></param>
        /// <returns></returns>
        public static GraphUserAccount ToGraphUserAccount(this ClaimsPrincipal claimsPrincipal)
        {
            if (claimsPrincipal == null)
            {
                throw new AuthenticationException(
                    new Error
                    {
                        Code = ErrorConstants.Codes.InvalidRequest,
                        Message = string.Format(ErrorConstants.Message.NullValue, "claimsPrincipal")
                    });
            }

            // Build GraphUserAccount from claims
            string objectId = claimsPrincipal.FindFirst(AuthConstants.ClaimTypes.ObjectIdUriSchema)?.Value;
            if (string.IsNullOrEmpty(objectId))
            {
                objectId = claimsPrincipal.FindFirst(AuthConstants.ClaimTypes.ObjectIdJwt)?.Value;
            }

            if (string.IsNullOrEmpty(objectId))
            {
                throw new AuthenticationException(
                    new Error
                    {
                        Code = ErrorConstants.Codes.InvalidClaim,
                        Message = string.Format(ErrorConstants.Message.MissingClaim, AuthConstants.ClaimTypes.ObjectIdUriSchema)
                    });
            }
                

            string tenentId = claimsPrincipal.FindFirst(AuthConstants.ClaimTypes.TenantIdUriSchema)?.Value;
            if (string.IsNullOrEmpty(tenentId))
            {
                tenentId = claimsPrincipal.FindFirst(AuthConstants.ClaimTypes.TenantIdJwt)?.Value;
            }

            if (string.IsNullOrEmpty(tenentId))
            {
                throw new AuthenticationException(
                    new Error
                    {
                        Code = ErrorConstants.Codes.InvalidClaim,
                        Message = string.Format(ErrorConstants.Message.MissingClaim, AuthConstants.ClaimTypes.TenantIdUriSchema)
                    });
            }

            string email = claimsPrincipal.FindFirst(AuthConstants.ClaimTypes.EmailUriSchema)?.Value;
            if (string.IsNullOrEmpty(email))
            {
                email = claimsPrincipal.FindFirst(AuthConstants.ClaimTypes.EmailJwt)?.Value;
            }

            return new GraphUserAccount() { Email = email, ObjectId = objectId, TenantId = tenentId };
        }
    }
}