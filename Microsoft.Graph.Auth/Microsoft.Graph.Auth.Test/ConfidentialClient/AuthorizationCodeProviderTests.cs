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
        private MockTokenCacheStorage tokenCacheStorage = new MockTokenCacheStorage();
        private AuthorizationCodeProvider authCodeFlowProvider;
        private IConfidentialClientApplication confidentialClientAppMock;
        private const string clientId = "client_id";
        private const string commonAuthority = "https://login.microsoftonline.com/common/";
        private const string organizationsAuthority = "https://login.microsoftonline.com/organizations/";
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
            authCodeFlowProvider = new AuthorizationCodeProvider(clientId, redirectUri, new ClientCredential(appSecret), tokenCacheStorage, scopes);
        }

        [TestMethod]
        public void AuthorizationCodeProvider_ConstructorWithoutAuthority()
        {
            Assert.IsInstanceOfType(authCodeFlowProvider, typeof(IAuthenticationProvider));
            Assert.IsNull(authCodeFlowProvider.ClientApplication);
            Assert.AreEqual(authCodeFlowProvider.ClientId, clientId);
            Assert.AreEqual(authCodeFlowProvider.RedirectUri, redirectUri);
            Assert.IsInstanceOfType(authCodeFlowProvider.UserTokenCache, typeof(ITokenCacheStorage));
        }

        [TestMethod]
        public void AuthorizationCodeProvider_ConstructorWithAuthority()
        {
            var authProvider = new AuthorizationCodeProvider(clientId, commonAuthority, redirectUri, new ClientCredential(appSecret), tokenCacheStorage, scopes);

            Assert.IsInstanceOfType(authProvider, typeof(IAuthenticationProvider));
            Assert.IsNull(authProvider.ClientApplication);
            Assert.AreEqual(authCodeFlowProvider.ClientId, clientId);
            Assert.AreEqual(authCodeFlowProvider.RedirectUri, redirectUri);
            Assert.IsInstanceOfType(authCodeFlowProvider.UserTokenCache, typeof(ITokenCacheStorage));
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
                Assert.IsInstanceOfType(ex, typeof(MsalUiRequiredException));
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