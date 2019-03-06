using System;
using Microsoft.Graph.Auth.Helpers;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Microsoft.Graph.Auth.Test.Helpers
{
    [TestClass]
    public class JwtHelpersTests
    {
        [TestMethod]
        public void Decode_ShouldDecodeValidJWTokenPayload()
        {
            string validToken = "eyJ0eXAiOiJKV1QiLCJub25jZSI6IkFBMjMyVEVTVCIsImFsZyI6IkhTMjU2In0.eyJmYW1pbHlfbmFtZSI6IkRvZSIsImdpdmVuX25hbWUiOiJKb2huIiwibmFtZSI6IkpvaG4gRG9lIiwib2lkIjoiZTYwMmFkYTctNmVmZC00ZTE4LWE5NzktNjNjMDJiOWYzYzc2Iiwic2NwIjoiVXNlci5SZWFkQmFzaWMuQWxsIiwidGlkIjoiNmJjMTUzMzUtZTJiOC00YTlhLTg2ODMtYTUyYTI2YzhjNTgzIiwidW5pcXVlX25hbWUiOiJqb2huQGRvZS50ZXN0LmNvbSIsInVwbiI6ImpvaG5AZG9lLnRlc3QuY29tIn0.hf9xI5XYBjGec - 4n4_Kxj8Nd2YHBtihdevYhzFxbpXQ";

            JwtPayload decodedJwtPayload = JwtHelpers.DecodeToObject<JwtPayload>(validToken.Split('.')[1]);

            Assert.IsNotNull(decodedJwtPayload, "Unexpected jwt payload decoded.");
            Assert.IsNotNull(decodedJwtPayload.Oid, "Unexpected oid set decoded.");
        }

        [TestMethod]
        public void Decode_ShouldThrowExceptionWhenInvalidJWTokenPayloadIsSet()
        {
            string validToken = "eyJ0eXAiOiJKV1QiLCJub25jZSI6IkFBMjMyVEVTVCIsImFsZyI6IkhTMjU2In0.eyJmYW1pbHlfbmFtZSI6IkRvZSIsImdpdmVuX25hbWUiOiJKb2huIiwibmFtZSI6IkpvaG4gRG9lIiwib2lkIjoiZTYwMmFkYTctNmVmZC00ZTE4LWE5NzktNjNjMDJiOWYzYzc2Iiwic2NwIjoiVXNlci5SZWFkQmFzaWMuQWxsIiwidGlkIjoiNmJjMTUzMzUtZTJiOC00YTlhLTg2ODMtYTUyYTI2YzhjNTgzIiwidW5pcXVlX25hbWUiOiJqb2huQGRvZS50ZXN0LmNvbSIsInVwbiI6ImpvaG5AZG9lLnRlc3QuY29tIn0.hf9xI5XYBjGec - 4n4_Kxj8Nd2YHBtihdevYhzFxbpXQ";

            AuthenticationException exception = Assert.ThrowsException<AuthenticationException>(() => JwtHelpers.DecodeToObject<JwtPayload>(validToken));
            Assert.AreEqual(exception.Error.Code, ErrorConstants.Codes.InvalidJWT);
            Assert.AreEqual(exception.Error.Message, ErrorConstants.Message.InvalidJWT);
        }
    }
}
