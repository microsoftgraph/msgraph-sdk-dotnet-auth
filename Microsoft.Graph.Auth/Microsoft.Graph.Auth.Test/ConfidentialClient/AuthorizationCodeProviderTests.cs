namespace Microsoft.Graph.Auth.Test.ConfidentialClient
{
    using Microsoft.Graph.Auth.Test.Mocks;
    using Microsoft.Identity.Client;
    using Microsoft.VisualStudio.TestTools.UnitTesting;
    using NSubstitute;
    using System;
    using System.Collections.Generic;
    using System.Net.Http;
    using System.Threading.Tasks;

    [TestClass]
    public class AuthorizationCodeProviderTests
    {
        private MockTokenCacheProvider tokenCacheProvider = new MockTokenCacheProvider();
        private AuthorizationCodeProvider authCodeFlowProvider;
        private IConfidentialClientApplication confidentialClientAppMock;
        private const string clientId = "client_id";
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
            authCodeFlowProvider = new AuthorizationCodeProvider(clientId, redirectUri, new ClientCredential(appSecret), tokenCacheProvider, scopes);
        }

        [TestMethod]
        public void AuthorizationCodeProvider_ConstructorWithNullNationalCloudAndTenant()
        {
            Assert.IsInstanceOfType(authCodeFlowProvider, typeof(IAuthenticationProvider));
            Assert.IsNull(authCodeFlowProvider.ClientApplication);
            Assert.AreEqual(authCodeFlowProvider.ClientId, clientId);
            Assert.AreEqual(authCodeFlowProvider.RedirectUri, redirectUri);
        }

        [TestMethod]
        public void AuthorizationCodeProvider_ConstructorWithNationalCloudAndTenant()
        {
            var authProvider = new AuthorizationCodeProvider(clientId, redirectUri, new ClientCredential(appSecret), tokenCacheProvider, scopes, NationalCloud.China, "contoso.com");

            Assert.IsInstanceOfType(authProvider, typeof(IAuthenticationProvider));
            Assert.IsNull(authProvider.ClientApplication);
            Assert.AreEqual(authCodeFlowProvider.ClientId, clientId);
            Assert.AreEqual(authCodeFlowProvider.RedirectUri, redirectUri);
        }

        [TestMethod]
        public void AuthorizationCodeProvider_ConstructorWithConfidentialClientApplication()
        {
            var confidentialClient = new ConfidentialClientApplication(clientId, redirectUri, new ClientCredential(appSecret), tokenCacheProvider.GetTokenCacheInstance(), null);
            var authProvider = new AuthorizationCodeProvider(confidentialClient, scopes);

            Assert.IsInstanceOfType(authProvider, typeof(IAuthenticationProvider));
            Assert.IsNotNull(authProvider.ClientApplication);
            Assert.IsInstanceOfType(authProvider.ClientApplication, typeof(IConfidentialClientApplication));
            Assert.AreEqual(authProvider.ClientApplication.ClientId, clientId);
            Assert.AreEqual(authProvider.ClientApplication.RedirectUri, redirectUri);
            Assert.AreEqual(authProvider.ClientApplication.Authority, "https://login.microsoftonline.com/common/");
        }

        [TestMethod]
        public async Task AuthorizationCodeProvider_WithNoUserAccountInCache()
        {
            var httpRequestMessage = new HttpRequestMessage(HttpMethod.Get, "http://example.org/foo");
            var expectedAuthResult = MockAuthResult.GetAuthenticationResult(scopes);
            
            confidentialClientAppMock.GetAccountsAsync().ReturnsForAnyArgs(new List<IAccount>());
            confidentialClientAppMock.AcquireTokenByAuthorizationCodeAsync(string.Empty, scopes).ReturnsForAnyArgs(expectedAuthResult);

            authCodeFlowProvider.ClientApplication = confidentialClientAppMock;

            try
            {
                await authCodeFlowProvider.AuthenticateRequestAsync(httpRequestMessage);
            }
            catch (Exception ex)
            {
                Assert.IsInstanceOfType(ex, typeof(MsalServiceException));
                Assert.AreEqual(ex.Message, MsalAuthErrorConstants.Message.AuthenticationChallengeRequired);
            }

            Assert.IsInstanceOfType(authCodeFlowProvider, typeof(IAuthenticationProvider));
            Assert.IsInstanceOfType(authCodeFlowProvider.ClientApplication, typeof(IConfidentialClientApplication));
            Assert.IsNull(httpRequestMessage.Headers.Authorization);
        }

        [TestMethod]
        public async Task AuthorizationCodeProvider_WithUserAccountInCache()
        {
            var httpRequestMessage = new HttpRequestMessage(HttpMethod.Get, "http://example.org/foo");
            var expectedAuthResult = MockAuthResult.GetAuthenticationResult(scopes);
            var mockAuthResult = MockAuthResult.GetAuthenticationResult(scopes);

            confidentialClientAppMock.GetAccountsAsync().ReturnsForAnyArgs(new List<IAccount> { mockUserAccount });
            confidentialClientAppMock.AcquireTokenSilentAsync(scopes, null).ReturnsForAnyArgs(expectedAuthResult);
            confidentialClientAppMock.AcquireTokenByAuthorizationCodeAsync(string.Empty, scopes).ReturnsForAnyArgs(mockAuthResult);

            AuthorizationCodeProvider authorizationCodeProvider = new AuthorizationCodeProvider(confidentialClientAppMock, scopes);
            await authorizationCodeProvider.AuthenticateRequestAsync(httpRequestMessage);

            Assert.IsInstanceOfType(authorizationCodeProvider, typeof(IAuthenticationProvider));
            Assert.IsInstanceOfType(authorizationCodeProvider.ClientApplication, typeof(IConfidentialClientApplication));
            Assert.IsNotNull(httpRequestMessage.Headers.Authorization);
            Assert.AreEqual(httpRequestMessage.Headers.Authorization.Scheme, CoreConstants.Headers.Bearer);
            Assert.AreEqual(httpRequestMessage.Headers.Authorization.Parameter, expectedAuthResult.AccessToken);
        }
    }
}