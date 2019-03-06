namespace Microsoft.Graph.Auth.Test.Extensions
{
    using Microsoft.Identity.Client;
    using System.Net.Http.Headers;
    using Microsoft.VisualStudio.TestTools.UnitTesting;
    using System.Net.Http;

    [TestClass]
    public class AuthenticationProviderExtensionsTests
    {
        [TestMethod]
        public void GetRetryAfter_ShouldThrowExceptionWhenRetryAfterHeaderIsNotSet()
        {
            string errorCode = "foo_error";
            IPublicClientApplication pca = DeviceCodeProvider.CreateClientApplication("clientId");
            DeviceCodeProvider authProvider = new DeviceCodeProvider(pca, new string[] { "foo.bar" });
            MsalServiceException msalServiceException = new MsalServiceException(errorCode, "bar_foo_error");

            MsalServiceException exception = Assert.ThrowsException<MsalServiceException>(() => authProvider.GetRetryAfter(msalServiceException));

            Assert.AreEqual(errorCode, exception.ErrorCode);
            Assert.AreEqual(ErrorConstants.Message.MissingRetryAfterHeader, exception.Message);
        }
    }
}
