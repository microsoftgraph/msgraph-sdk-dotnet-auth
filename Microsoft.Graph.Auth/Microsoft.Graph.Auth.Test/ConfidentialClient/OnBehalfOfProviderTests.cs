namespace Microsoft.Graph.Auth.Test.ConfidentialClient
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Net.Http;
    using System.Threading.Tasks;
    using Microsoft.Graph.Auth.Test.Mocks;
    using Microsoft.Identity.Client;
    using Microsoft.VisualStudio.TestTools.UnitTesting;

    [TestClass]
    public class OnBehalfOfProviderTests
    {
        private MockConfidentialClientApplication mockClientApplicationBase;
        private IEnumerable<MockUserAccount> mockUserAccounts;
        private AuthenticationResult mockAuthResult;
        private OnBehalfOfProvider onBehalfOfProvider;
        private UserAssertion userAssertion;
        private const string clientId = "client-id";
        private const string redirectUri = "redirectUri";
        private const string appSecret = "appSecret";
        private string[] scopes = new string[] { "User.Read" };
        private string commonAuthority = "https://login.microsoftonline.com/common/";

        [TestInitialize]
        public void Setup()
        {
            mockUserAccounts = new List<MockUserAccount>
            {
                new MockUserAccount("xyz@test.net", "login.microsoftonline.com")
            };
            mockAuthResult = MockAuthResult.GetAuthenticationResult(scopes);
            mockClientApplicationBase = new MockConfidentialClientApplication(scopes, mockUserAccounts, commonAuthority, false, clientId, mockAuthResult);
            onBehalfOfProvider = new OnBehalfOfProvider(mockClientApplicationBase.Object, scopes, userAssertion);
        }

        [TestMethod]
        public void OnBehalfOfProvider_DefaultConstructor()
        {
            Assert.IsInstanceOfType(onBehalfOfProvider, typeof(IAuthenticationProvider));
            Assert.IsNotNull(onBehalfOfProvider.ClientApplication);
            Assert.IsInstanceOfType(onBehalfOfProvider.ClientApplication, typeof(IConfidentialClientApplication));
            Assert.AreEqual(onBehalfOfProvider.ClientApplication.ClientId, clientId);
            Assert.AreEqual(onBehalfOfProvider.ClientApplication.Authority, commonAuthority);
        }

        [TestMethod]
        public async Task OnBehalfOfProvider_WithNoUserAccountInCache()
        {
            var httpRequestMessage = new HttpRequestMessage(HttpMethod.Get, "http://example.org/foo");
            var expectedAuthResult = MockAuthResult.GetAuthenticationResult(scopes);
            var mockAuthResult = MockAuthResult.GetAuthenticationResult(scopes);

            mockClientApplicationBase.Setup(cca => cca.GetAccountsAsync())
            .Returns(Task.FromResult(new List<IAccount>().AsEnumerable()));

            mockClientApplicationBase.Setup(cca => cca.AcquireTokenOnBehalfOfAsync(scopes, userAssertion, "https://login.microsoftonline.com/common/"))
            .Returns(Task.FromResult(expectedAuthResult));

            onBehalfOfProvider.ClientApplication = mockClientApplicationBase.Object;

            await onBehalfOfProvider.AuthenticateRequestAsync(httpRequestMessage);

            Assert.IsInstanceOfType(onBehalfOfProvider, typeof(IAuthenticationProvider));
            Assert.IsInstanceOfType(onBehalfOfProvider.ClientApplication, typeof(IConfidentialClientApplication));
            Assert.IsNotNull(httpRequestMessage.Headers.Authorization);
            Assert.AreEqual(httpRequestMessage.Headers.Authorization.Scheme, CoreConstants.Headers.Bearer);
            Assert.AreEqual(httpRequestMessage.Headers.Authorization.Parameter, expectedAuthResult.AccessToken);
        }

        [TestMethod]
        public async Task OnBehalfOfProvider_WithUserAccountInCache()
        {
            var httpRequestMessage = new HttpRequestMessage(HttpMethod.Get, "http://example.org/foo");
            await onBehalfOfProvider.AuthenticateRequestAsync(httpRequestMessage);

            Assert.IsInstanceOfType(onBehalfOfProvider, typeof(IAuthenticationProvider));
            Assert.IsInstanceOfType(onBehalfOfProvider.ClientApplication, typeof(IConfidentialClientApplication));
            Assert.IsNotNull(httpRequestMessage.Headers.Authorization);
            Assert.AreEqual(httpRequestMessage.Headers.Authorization.Scheme, CoreConstants.Headers.Bearer);
            Assert.AreEqual(httpRequestMessage.Headers.Authorization.Parameter, mockAuthResult.AccessToken);
        }
    }
}
