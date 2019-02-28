namespace Microsoft.Graph.Auth
{
    using System.Security.Claims;
    public static class ClaimsPrincipalExtensions
    {
        public static GraphUserAccount ToGraphUserAccount(this ClaimsPrincipal claimsPrincipal)
        {
            if (claimsPrincipal == null)
            {
                throw new GraphAuthException(
                    new Error
                    {
                        Code = ErrorConstants.Codes.InvalidRequest,
                        Message = string.Format(ErrorConstants.Message.NullValue, "claimsPrincipal")
                    });
            }

            // Build GraphUserAccount from claims
            string objectId = claimsPrincipal.FindFirst("http://schemas.microsoft.com/identity/claims/objectidentifier")?.Value;
            if (string.IsNullOrEmpty(objectId))
            {
                objectId = claimsPrincipal.FindFirst("oid")?.Value;
            }

            if (string.IsNullOrEmpty(objectId))
            {
                throw new GraphAuthException(
                    new Error
                    {
                        Code = ErrorConstants.Codes.InvalidClaim,
                        Message = string.Format(ErrorConstants.Message.MissingClaim, "http://schemas.microsoft.com/identity/claims/objectidentifier")
                    });
            }
                

            string tenentId = claimsPrincipal.FindFirst("http://schemas.microsoft.com/identity/claims/tenantid")?.Value;
            if (string.IsNullOrEmpty(tenentId))
            {
                tenentId = claimsPrincipal.FindFirst("tid")?.Value;
            }

            if (string.IsNullOrEmpty(tenentId))
            {
                throw new GraphAuthException(
                    new Error
                    {
                        Code = ErrorConstants.Codes.InvalidClaim,
                        Message = string.Format(ErrorConstants.Message.MissingClaim, "http://schemas.microsoft.com/identity/claims/tenantid")
                    });
            }

            string email = claimsPrincipal.FindFirst("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress")?.Value;
            if (string.IsNullOrEmpty(email))
            {
                email = claimsPrincipal.FindFirst("preferred_username")?.Value;
            }

            return new GraphUserAccount() { Email = email, ObjectId = objectId, TenantId = tenentId };
        }
    }
}
