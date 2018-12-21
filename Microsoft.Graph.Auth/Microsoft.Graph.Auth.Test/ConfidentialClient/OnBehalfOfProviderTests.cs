namespace Microsoft.Graph.Auth.Test.ConfidentialClient
{
    using System;
    using System.Collections.Generic;
    using System.Net.Http;
    using System.Threading.Tasks;
    using Microsoft.Graph.Auth.Test.Mocks;
    using Microsoft.Identity.Client;
    using Microsoft.VisualStudio.TestTools.UnitTesting;
    using NSubstitute;

    [TestClass]
    public class OnBehalfOfProviderTests
    {
        private MockTokenCacheProvider tokenCacheProvider;
        private UserAssertion userAssertion;
        private OnBehalfOfProvider authCodeFlowProvider;
        private IConfidentialClientApplication confidentialClientAppMock;
        private const string clientId = "client-id";
        private string[] scopes = new string[] { "User.Read" };
        private MockUserAccount mockUserAccount, mockUserAccount2;
        private const string redirectUri = "redirectUri";
        private const string appSecret = "appSecret";

        [TestInitialize]
        public void Setup()
        {
            mockUserAccount = new MockUserAccount("xyz@test.net", "login.microsoftonline.com");
            mockUserAccount2 = new MockUserAccount("abc@test.com", "login.microsoftonline.com");
            confidentialClientAppMock = Substitute.For<IConfidentialClientApplication>();
            tokenCacheProvider = new MockTokenCacheProvider();
            var mockAuthResult = MockAuthResult.GetAuthenticationResult(scopes);
            userAssertion = new UserAssertion(mockAuthResult.AccessToken);
            authCodeFlowProvider = new OnBehalfOfProvider(clientId, redirectUri, new ClientCredential(appSecret), tokenCacheProvider, scopes, userAssertion);
        }

        [TestMethod]
        public void OnBehalfOfProvider_ConstructorWithNullNationalCloudAndTenant()
        {
            Assert.IsInstanceOfType(authCodeFlowProvider, typeof(IAuthenticationProvider));
            Assert.IsNotNull(authCodeFlowProvider.ClientApplication);
            Assert.IsInstanceOfType(authCodeFlowProvider.ClientApplication, typeof(IConfidentialClientApplication));
            Assert.AreEqual(authCodeFlowProvider.ClientApplication.ClientId, clientId);
            Assert.AreEqual(authCodeFlowProvider.ClientApplication.RedirectUri, redirectUri);
            Assert.AreEqual(authCodeFlowProvider.ClientApplication.Authority, "https://login.microsoftonline.com/common/");
        }

        [TestMethod]
        public void OnBehalfOfProvider_ConstructorWithNationalCloudAndTenant()
        {
            var authProvider = new OnBehalfOfProvider(clientId, redirectUri, new ClientCredential(appSecret), tokenCacheProvider, scopes, userAssertion, NationalCloud.Global, "foo");

            Assert.IsInstanceOfType(authProvider, typeof(IAuthenticationProvider));
            Assert.IsNotNull(authProvider.ClientApplication);
            Assert.IsInstanceOfType(authProvider.ClientApplication, typeof(IConfidentialClientApplication));
            Assert.AreEqual(authProvider.ClientApplication.ClientId, clientId);
            Assert.AreEqual(authProvider.ClientApplication.RedirectUri, redirectUri);
            Assert.AreEqual(authProvider.ClientApplication.Authority, "https://login.microsoftonline.com/foo/");
        }

        [TestMethod]
        public void OnBehalfOfProvider_ConstructorWithConfidentialClientApplication()
        {
            var confidentialClient = new ConfidentialClientApplication(clientId, redirectUri, new ClientCredential(appSecret), tokenCacheProvider.GetTokenCacheInstance(), null);
            var authProvider = new OnBehalfOfProvider(confidentialClient, scopes, userAssertion);

            Assert.IsInstanceOfType(authProvider, typeof(IAuthenticationProvider));
            Assert.IsNotNull(authProvider.ClientApplication);
            Assert.IsInstanceOfType(authProvider.ClientApplication, typeof(IConfidentialClientApplication));
            Assert.AreEqual(authProvider.ClientApplication.ClientId, clientId);
            Assert.AreEqual(authProvider.ClientApplication.RedirectUri, redirectUri);
            Assert.AreEqual(authProvider.ClientApplication.Authority, "https://login.microsoftonline.com/common/");
        }

        [TestMethod]
        public async Task OnBehalfOfProvider_WithNoUserAccountInCache()
        {
            var httpRequestMessage = new HttpRequestMessage(HttpMethod.Get, "http://example.org/foo");
            var expectedAuthResult = MockAuthResult.GetAuthenticationResult(scopes);
            var mockAuthResult = MockAuthResult.GetAuthenticationResult(scopes);

            confidentialClientAppMock.GetAccountsAsync().ReturnsForAnyArgs(new List<IAccount>());
            confidentialClientAppMock.AcquireTokenSilentAsync(scopes, mockUserAccount).ReturnsForAnyArgs(mockAuthResult);
            confidentialClientAppMock.AcquireTokenOnBehalfOfAsync(scopes, userAssertion, "https://login.microsoftonline.com/common/").ReturnsForAnyArgs(expectedAuthResult);

            authCodeFlowProvider.ClientApplication = confidentialClientAppMock;

            try
            {
                await authCodeFlowProvider.AuthenticateRequestAsync(httpRequestMessage);
            }
            catch (Exception ex)
            {
                Assert.IsInstanceOfType(ex, typeof(MsalUiRequiredException));
                Assert.AreEqual(ex.Message, MsalAuthErrorConstants.Message.AuthenticationChallengeRequired);
            }

            Assert.IsInstanceOfType(authCodeFlowProvider, typeof(IAuthenticationProvider));
            Assert.IsInstanceOfType(authCodeFlowProvider.ClientApplication, typeof(IConfidentialClientApplication));
            Assert.IsNotNull(httpRequestMessage.Headers.Authorization);
            Assert.AreEqual(httpRequestMessage.Headers.Authorization.Scheme, CoreConstants.Headers.Bearer);
            Assert.AreEqual(httpRequestMessage.Headers.Authorization.Parameter, expectedAuthResult.AccessToken);
        }

        [TestMethod]
        public async Task OnBehalfOfProvider_WithUserAccountInCache()
        {
            var httpRequestMessage = new HttpRequestMessage(HttpMethod.Get, "http://example.org/foo");
            var expectedAuthResult = MockAuthResult.GetAuthenticationResult(scopes);
            var mockAuthResult = MockAuthResult.GetAuthenticationResult(scopes);

            confidentialClientAppMock.GetAccountsAsync().ReturnsForAnyArgs(new List<IAccount> { mockUserAccount });
            confidentialClientAppMock.AcquireTokenSilentAsync(scopes, null).ReturnsForAnyArgs(expectedAuthResult);
            confidentialClientAppMock.AcquireTokenOnBehalfOfAsync(scopes, userAssertion, "https://login.microsoftonline.com/common/").ReturnsForAnyArgs(mockAuthResult);

            authCodeFlowProvider.ClientApplication = confidentialClientAppMock;

            await authCodeFlowProvider.AuthenticateRequestAsync(httpRequestMessage);

            Assert.IsInstanceOfType(authCodeFlowProvider, typeof(IAuthenticationProvider));
            Assert.IsInstanceOfType(authCodeFlowProvider.ClientApplication, typeof(IConfidentialClientApplication));
            Assert.IsNotNull(httpRequestMessage.Headers.Authorization);
            Assert.AreEqual(httpRequestMessage.Headers.Authorization.Scheme, CoreConstants.Headers.Bearer);
            Assert.AreEqual(httpRequestMessage.Headers.Authorization.Parameter, expectedAuthResult.AccessToken);
        }
    }
}
