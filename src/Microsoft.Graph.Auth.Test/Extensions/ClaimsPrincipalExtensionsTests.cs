namespace Microsoft.Graph.Auth.Test.Extensions
{
    using System;
    using System.Collections.Generic;
    using System.Security.Claims;
    using Microsoft.VisualStudio.TestTools.UnitTesting;

    [TestClass]
    public class ClaimsPrincipalExtensionsTests
    {
        [TestMethod]
        public void ToGraphUserAccount_ShouldThrowExceptionWhenClaimsPrincipalIsNull()
        {
            ClaimsPrincipal claimsPrincipal = null;
            AuthenticationException authException = Assert.ThrowsException<AuthenticationException>(() => claimsPrincipal.ToGraphUserAccount());

            Assert.AreEqual(ErrorConstants.Codes.InvalidRequest, authException.Error.Code, "Unexpected error code set.");
            Assert.AreEqual(string.Format(ErrorConstants.Message.NullValue, "claimsPrincipal"), authException.Error.Message, "Unexpected error message set.");
        }

        [TestMethod]
        public void ToGraphUserAccount_ShouldThrowExceptionWhenClaimsPrincipalHasNoClaims()
        {
            ClaimsPrincipal claimsPrincipal = new ClaimsPrincipal();
            AuthenticationException authException = Assert.ThrowsException<AuthenticationException>(() => claimsPrincipal.ToGraphUserAccount());

            Assert.AreEqual(ErrorConstants.Codes.InvalidClaim, authException.Error.Code, "Unexpected error code set.");
            Assert.AreEqual(string.Format(ErrorConstants.Message.MissingClaim, AuthConstants.ClaimTypes.ObjectIdUriSchema), authException.Error.Message, "Unexpected error message set.");
        }

        [TestMethod]
        public void ToGraphUserAccount_ShouldThrowExceptionWhenClaimsPrincipalHasNoTenantIdClaims()
        {
            string objectId = Guid.NewGuid().ToString();
            string email = "foo@bar.com";
            List<Claim> claims = new List<Claim>
            {
                new Claim(AuthConstants.ClaimTypes.ObjectIdUriSchema, objectId),
                new Claim(AuthConstants.ClaimTypes.EmailJwt, email),
            };
            ClaimsPrincipal claimsPrincipal = new ClaimsPrincipal(new ClaimsIdentity(claims));
            AuthenticationException authException = Assert.ThrowsException<AuthenticationException>(() => claimsPrincipal.ToGraphUserAccount());

            Assert.AreEqual(ErrorConstants.Codes.InvalidClaim, authException.Error.Code, "Unexpected error code set.");
            Assert.AreEqual(string.Format(ErrorConstants.Message.MissingClaim, AuthConstants.ClaimTypes.TenantIdUriSchema), authException.Error.Message, "Unexpected error message set.");
        }

        [TestMethod]
        public void ToGraphUserAccount_ShouldReturnGraphUserAccountWhenClaimsArePresent()
        {
            string objectId = Guid.NewGuid().ToString();
            string tenantId = Guid.NewGuid().ToString();
            string email = "foo@bar.com";
            List<Claim> claims = new List<Claim>
            {
                new Claim(AuthConstants.ClaimTypes.ObjectIdUriSchema, objectId),
                new Claim(AuthConstants.ClaimTypes.TenantIdJwt, tenantId),
                new Claim(AuthConstants.ClaimTypes.EmailUriSchema, email),
            };
            ClaimsPrincipal claimsPrincipal = new ClaimsPrincipal(new ClaimsIdentity(claims));

            GraphUserAccount graphUserAccount = claimsPrincipal.ToGraphUserAccount();

            Assert.AreEqual(objectId, graphUserAccount.ObjectId, "Unexpected objcetId set.");
            Assert.AreEqual(tenantId, graphUserAccount.TenantId, "Unexpected tenantId set.");
            Assert.AreEqual(email, graphUserAccount.Email, "Unexpected email set.");
        }
    }
}
