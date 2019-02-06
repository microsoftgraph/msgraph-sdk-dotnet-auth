namespace Microsoft.Graph.Auth.Test.PublicClient
{
    using Microsoft.Graph.Auth.Test.Mocks;
    using Microsoft.Identity.Client;
    using Microsoft.VisualStudio.TestTools.UnitTesting;
    using System.Collections.Generic;
    using System.Linq;
    using System.Net.Http;
    using System.Threading.Tasks;

    [TestClass]
    public class InteractiveAuthenticationProviderTests
    {
        private MockPublicClientApplication mockClientApplicationBase;
        private IEnumerable<MockUserAccount> mockUserAccounts;
        private AuthenticationResult mockAuthResult;
        private InteractiveAuthenticationProvider interactiveAuthProvider;
        private const string clientId = "client-id";
        private const string redirectUri = "redirectUri";
        private const string appSecret = "appSecret";
        private string commonAuthority = "https://login.microsoftonline.com/common/";
        private string[] scopes = new string[] { "User.Read" };

        [TestInitialize]
        public void Setup()
        {
            mockUserAccounts = new List<MockUserAccount> {
                new MockUserAccount("xyz@test.net", "login.microsoftonline.com")
            };
            mockAuthResult = MockAuthResult.GetAuthenticationResult(scopes);
            mockClientApplicationBase = new MockPublicClientApplication(scopes, mockUserAccounts, commonAuthority, false, clientId, mockAuthResult);
            interactiveAuthProvider = new InteractiveAuthenticationProvider(mockClientApplicationBase.Object, scopes);
        }

        [TestMethod]
        public void InteractiveAuthenticationProvider_LoginHintConstructor()
        {
            Assert.IsInstanceOfType(interactiveAuthProvider, typeof(IAuthenticationProvider));
            Assert.IsNotNull(interactiveAuthProvider.ClientApplication);
            Assert.IsInstanceOfType(interactiveAuthProvider.ClientApplication, typeof(IPublicClientApplication));
            Assert.AreEqual(interactiveAuthProvider.ClientApplication.ClientId, clientId);
            Assert.AreEqual(interactiveAuthProvider.ClientApplication.Authority, "https://login.microsoftonline.com/common/");
        }

        [TestMethod]
        public void InteractiveAuthenticationProvider_AccountConstructor()
        {
            var authProvider = new InteractiveAuthenticationProvider(mockClientApplicationBase.Object, scopes);

            Assert.IsInstanceOfType(authProvider, typeof(IAuthenticationProvider));
            Assert.IsNotNull(authProvider.ClientApplication);
            Assert.IsInstanceOfType(authProvider.ClientApplication, typeof(IPublicClientApplication));
            Assert.AreEqual(authProvider.ClientApplication.ClientId, clientId);
            Assert.AreEqual(authProvider.ClientApplication.Authority, "https://login.microsoftonline.com/common/");
        }

        [TestMethod]
        public async Task InteractiveAuthenticationProvider_WithNoUserAccountInCache()
        {
            var httpRequestMessage = new HttpRequestMessage(HttpMethod.Get, "http://example.org/foo");
            var expectedAuthResult = MockAuthResult.GetAuthenticationResult(scopes);
            var mockAuthResult = MockAuthResult.GetAuthenticationResult(scopes);

            mockClientApplicationBase.Setup(pca => pca.GetAccountsAsync())
                .Returns(Task.FromResult(new List<IAccount>().AsEnumerable()));
            var accounts = await mockClientApplicationBase.Object.GetAccountsAsync();
            mockClientApplicationBase.Setup(pca => pca.AcquireTokenAsync(scopes, accounts.FirstOrDefault(), UIBehavior.SelectAccount, null, null, commonAuthority, null))
                .Returns(Task.FromResult(expectedAuthResult));

            interactiveAuthProvider.ClientApplication = mockClientApplicationBase.Object;

            await interactiveAuthProvider.AuthenticateRequestAsync(httpRequestMessage);

            Assert.IsInstanceOfType(interactiveAuthProvider, typeof(IAuthenticationProvider));
            Assert.IsInstanceOfType(interactiveAuthProvider.ClientApplication, typeof(IPublicClientApplication));
            Assert.IsNotNull(httpRequestMessage.Headers.Authorization);
            Assert.AreEqual(httpRequestMessage.Headers.Authorization.Scheme, CoreConstants.Headers.Bearer);
            Assert.AreEqual(httpRequestMessage.Headers.Authorization.Parameter, expectedAuthResult.AccessToken);
        }

        [TestMethod]
        public async Task InteractiveAuthenticationProvider_WithUserAccountInCache()
        {
            var httpRequestMessage = new HttpRequestMessage(HttpMethod.Post, "http://example.org/foo");
            
            await interactiveAuthProvider.AuthenticateRequestAsync(httpRequestMessage);

            Assert.IsInstanceOfType(interactiveAuthProvider, typeof(IAuthenticationProvider));
            Assert.IsInstanceOfType(interactiveAuthProvider.ClientApplication, typeof(IPublicClientApplication));
            Assert.IsNotNull(httpRequestMessage.Headers.Authorization);
            Assert.AreEqual(httpRequestMessage.Headers.Authorization.Scheme, CoreConstants.Headers.Bearer);
            Assert.AreEqual(httpRequestMessage.Headers.Authorization.Parameter, mockAuthResult.AccessToken);
        }
    }
}
