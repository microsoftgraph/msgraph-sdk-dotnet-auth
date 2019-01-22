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
    public class IntegratedWindowsAuthenticationProviderTests
    {
        private MockPublicClientApplication mockClientApplicationBase;
        private IEnumerable<MockUserAccount> mockUserAccounts;
        private AuthenticationResult mockAuthResult;
        private IntegratedWindowsAuthenticationProvider intergratedWindowsAuthProvider;
        private const string clientId = "client-id";
        private const string redirectUri = "redirectUri";
        private const string appSecret = "appSecret";
        private string organizationsAuthority = "https://login.microsoftonline.com/organizations/";
        private string[] scopes = new string[] { "User.Read" };

        [TestInitialize]
        public void Setup()
        {
            mockUserAccounts = new List<MockUserAccount> {
                new MockUserAccount("xyz@test.net", "login.microsoftonline.com")
            };
            mockAuthResult = MockAuthResult.GetAuthenticationResult(scopes);
            mockClientApplicationBase = new MockPublicClientApplication(scopes, mockUserAccounts, organizationsAuthority, false, clientId, mockAuthResult);
            intergratedWindowsAuthProvider = new IntegratedWindowsAuthenticationProvider(mockClientApplicationBase.Object, scopes);
        }

        [TestMethod]
        public void IntegratedWindowsAuthenticationProvider_DefaulltConstructor()
        {
            Assert.IsInstanceOfType(intergratedWindowsAuthProvider, typeof(IAuthenticationProvider));
            Assert.IsNotNull(intergratedWindowsAuthProvider.ClientApplication);
            Assert.IsInstanceOfType(intergratedWindowsAuthProvider.ClientApplication, typeof(IPublicClientApplication));
            Assert.AreEqual(intergratedWindowsAuthProvider.ClientApplication.ClientId, clientId);
            Assert.AreEqual(intergratedWindowsAuthProvider.ClientApplication.Authority, "https://login.microsoftonline.com/organizations/");
        }

        [TestMethod]
        public async Task IntegratedWindowsAuthenticationProvider_WithNoUserAccountInCache()
        {
            var httpRequestMessage = new HttpRequestMessage(HttpMethod.Get, "http://example.org/foo");
            var expectedAuthResult = MockAuthResult.GetAuthenticationResult(scopes);

            mockClientApplicationBase.Setup(pca => pca.GetAccountsAsync())
                .Returns(Task.FromResult(new List<IAccount>().AsEnumerable()));

            mockClientApplicationBase.Setup(pca => pca.AcquireTokenByIntegratedWindowsAuthAsync(scopes))
                .Returns(Task.FromResult(expectedAuthResult));

            intergratedWindowsAuthProvider.ClientApplication = mockClientApplicationBase.Object;

            await intergratedWindowsAuthProvider.AuthenticateRequestAsync(httpRequestMessage);

            Assert.IsInstanceOfType(intergratedWindowsAuthProvider, typeof(IAuthenticationProvider));
            Assert.IsInstanceOfType(intergratedWindowsAuthProvider.ClientApplication, typeof(IPublicClientApplication));
            Assert.IsNotNull(httpRequestMessage.Headers.Authorization);
            Assert.AreEqual(httpRequestMessage.Headers.Authorization.Scheme, CoreConstants.Headers.Bearer);
            Assert.AreEqual(httpRequestMessage.Headers.Authorization.Parameter, expectedAuthResult.AccessToken);
        }

        [TestMethod]
        public async Task IntegratedWindowsAuthenticationProvider_WithUserAccountInCache()
        {
            var httpRequestMessage = new HttpRequestMessage(HttpMethod.Post, "http://example.org/foo");
            var expectedAuthResult = MockAuthResult.GetAuthenticationResult(scopes);

            await intergratedWindowsAuthProvider.AuthenticateRequestAsync(httpRequestMessage);

            Assert.IsInstanceOfType(intergratedWindowsAuthProvider, typeof(IAuthenticationProvider));
            Assert.IsInstanceOfType(intergratedWindowsAuthProvider.ClientApplication, typeof(IPublicClientApplication));
            Assert.IsNotNull(httpRequestMessage.Headers.Authorization);
            Assert.AreEqual(httpRequestMessage.Headers.Authorization.Scheme, CoreConstants.Headers.Bearer);
            Assert.AreEqual(httpRequestMessage.Headers.Authorization.Parameter, mockAuthResult.AccessToken);
        }
    }
}
