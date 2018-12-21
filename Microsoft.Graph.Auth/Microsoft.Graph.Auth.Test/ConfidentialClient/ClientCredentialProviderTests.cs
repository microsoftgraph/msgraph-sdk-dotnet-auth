using Microsoft.Graph.Auth.Test.Mocks;
using Microsoft.Identity.Client;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using NSubstitute;
using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading.Tasks;

namespace Microsoft.Graph.Auth.Test.ConfidentialClient
{
    [TestClass]
    public class ClientCredentialProviderTests
    {
        private MockTokenCacheProvider tokenCacheProvider;
        private UserAssertion userAssertion;
        private ClientCredentialProvider clientCredentialFlowProvider;
        private IConfidentialClientApplication confidentialClientAppMock;
        private const string clientId = "client-id";
        private const string resourceUrl = "https://graph.microsoft.com";
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

            clientCredentialFlowProvider = new ClientCredentialProvider(clientId, redirectUri, new ClientCredential(appSecret), tokenCacheProvider);
        }

        [TestMethod]
        public void ClientCredentialProvider_ConstructorWithNullNationalCloudAndTenant()
        {
            Assert.IsInstanceOfType(clientCredentialFlowProvider, typeof(IAuthenticationProvider));
            Assert.IsNotNull(clientCredentialFlowProvider.ClientApplication);
            Assert.IsInstanceOfType(clientCredentialFlowProvider.ClientApplication, typeof(IConfidentialClientApplication));
            Assert.AreEqual(clientCredentialFlowProvider.ClientApplication.ClientId, clientId);
            Assert.AreEqual(clientCredentialFlowProvider.ClientApplication.RedirectUri, redirectUri);
            Assert.AreEqual(clientCredentialFlowProvider.ClientApplication.Authority, "https://login.microsoftonline.com/common/");
        }

        [TestMethod]
        public void ClientCredentialProvider_ConstructorWithNationalCloudAndTenant()
        {
            var authProvider = new ClientCredentialProvider(clientId, redirectUri, new ClientCredential(appSecret), tokenCacheProvider, NationalCloud.Germany, "organizations");

            Assert.IsInstanceOfType(authProvider, typeof(IAuthenticationProvider));
            Assert.IsNotNull(authProvider.ClientApplication);
            Assert.IsInstanceOfType(authProvider.ClientApplication, typeof(IConfidentialClientApplication));
            Assert.AreEqual(authProvider.ClientApplication.ClientId, clientId);
            Assert.AreEqual(authProvider.ClientApplication.RedirectUri, redirectUri);
            Assert.AreEqual(authProvider.ClientApplication.Authority, "https://login.microsoftonline.de/organizations/");
        }

        [TestMethod]
        public void ClientCredentialProvider_ConstructorWithConfidentialClientApplication()
        {
            var confidentialClient = new ConfidentialClientApplication(clientId, redirectUri, new ClientCredential(appSecret), tokenCacheProvider.GetTokenCacheInstance(), null);
            var authProvider = new ClientCredentialProvider(confidentialClient);

            Assert.IsInstanceOfType(authProvider, typeof(IAuthenticationProvider));
            Assert.IsNotNull(authProvider.ClientApplication);
            Assert.IsInstanceOfType(authProvider.ClientApplication, typeof(IConfidentialClientApplication));
            Assert.AreEqual(authProvider.ClientApplication.ClientId, clientId);
            Assert.AreEqual(authProvider.ClientApplication.RedirectUri, redirectUri);
            Assert.AreEqual(authProvider.ClientApplication.Authority, "https://login.microsoftonline.com/common/");
        }

        [TestMethod]
        public async Task ClientCredentialProvider_WithNoUserAccountInCache()
        {
            var httpRequestMessage = new HttpRequestMessage(HttpMethod.Get, "http://example.org/foo");
            var expectedAuthResult = MockAuthResult.GetAuthenticationResult(scopes);
            var mockAuthResult = MockAuthResult.GetAuthenticationResult(scopes);

            confidentialClientAppMock.GetAccountsAsync().ReturnsForAnyArgs(new List<IAccount>());
            confidentialClientAppMock.AcquireTokenForClientAsync(new string[] { resourceUrl + "/.default"}).ReturnsForAnyArgs(expectedAuthResult);

            clientCredentialFlowProvider.ClientApplication = confidentialClientAppMock;

            try
            {
                await clientCredentialFlowProvider.AuthenticateRequestAsync(httpRequestMessage);
            }
            catch (Exception ex)
            {
                Assert.IsInstanceOfType(ex, typeof(MsalUiRequiredException));
                Assert.AreEqual(ex.Message, MsalAuthErrorConstants.Message.AuthenticationChallengeRequired);
            }

            Assert.IsInstanceOfType(clientCredentialFlowProvider, typeof(IAuthenticationProvider));
            Assert.IsInstanceOfType(clientCredentialFlowProvider.ClientApplication, typeof(IConfidentialClientApplication));
            Assert.IsNotNull(httpRequestMessage.Headers.Authorization);
            Assert.AreEqual(httpRequestMessage.Headers.Authorization.Scheme, CoreConstants.Headers.Bearer);
            Assert.AreEqual(httpRequestMessage.Headers.Authorization.Parameter, expectedAuthResult.AccessToken);
        }

        [TestMethod]
        public async Task ClientCredentialProvider_WithUserAccountInCache()
        {
            var httpRequestMessage = new HttpRequestMessage(HttpMethod.Get, "http://example.org/foo");
            var expectedAuthResult = MockAuthResult.GetAuthenticationResult(scopes);
            var mockAuthResult = MockAuthResult.GetAuthenticationResult(scopes);

            confidentialClientAppMock.GetAccountsAsync().ReturnsForAnyArgs(new List<IAccount> { mockUserAccount });
            confidentialClientAppMock.AcquireTokenSilentAsync(scopes, null).ReturnsForAnyArgs(mockAuthResult);
            confidentialClientAppMock.AcquireTokenForClientAsync(new string[] { resourceUrl + "/.default" }).ReturnsForAnyArgs(expectedAuthResult);
            confidentialClientAppMock.AcquireTokenForClientAsync(new string[] { resourceUrl + "/.default" }, false).ReturnsForAnyArgs(mockAuthResult);

            clientCredentialFlowProvider.ClientApplication = confidentialClientAppMock;

            await clientCredentialFlowProvider.AuthenticateRequestAsync(httpRequestMessage);

            Assert.IsInstanceOfType(clientCredentialFlowProvider, typeof(IAuthenticationProvider));
            Assert.IsInstanceOfType(clientCredentialFlowProvider.ClientApplication, typeof(IConfidentialClientApplication));
            Assert.IsNotNull(httpRequestMessage.Headers.Authorization);
            Assert.AreEqual(httpRequestMessage.Headers.Authorization.Scheme, CoreConstants.Headers.Bearer);
            Assert.AreEqual(httpRequestMessage.Headers.Authorization.Parameter, expectedAuthResult.AccessToken);
        }
    }
}
