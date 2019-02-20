namespace Microsoft.Graph.Auth.Test.PublicClient
{
    using Microsoft.Graph.Auth.Test.Mocks;
    using Microsoft.Identity.Client;
    using Microsoft.VisualStudio.TestTools.UnitTesting;
    using System.Collections.Generic;
    using System.Linq;
    using System.Net.Http;
    using System.Security;
    using System.Threading.Tasks;

    [TestClass]
    public class UsernamePasswordProviderTests
    {
        private SecureString securePassword;
        private MockPublicClientApplication mockClientApplicationBase;
        private IEnumerable<MockUserAccount> mockUserAccounts;
        private AuthenticationResult mockAuthResult;
        private UsernamePasswordProvider usernamePasswordProvider;
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
            usernamePasswordProvider = new UsernamePasswordProvider(mockClientApplicationBase.Object as IPublicClientApplication, scopes, mockUserAccounts.FirstOrDefault().Username, securePassword);
        }

        [TestMethod]
        public void UsernamePasswordProvider_DefaultConstructor()
        {
            Assert.IsInstanceOfType(usernamePasswordProvider, typeof(IAuthenticationProvider));
            Assert.IsNotNull(usernamePasswordProvider.ClientApplication);
            Assert.IsInstanceOfType(usernamePasswordProvider.ClientApplication, typeof(IPublicClientApplication));
            Assert.AreEqual(usernamePasswordProvider.ClientApplication.ClientId, clientId);
            Assert.AreEqual(usernamePasswordProvider.ClientApplication.Authority, "https://login.microsoftonline.com/organizations/");
        }

        [TestMethod]
        public async Task UsernamePasswordProvider_WithNoUserAccountInCache()
        {
            var httpRequestMessage = new HttpRequestMessage(HttpMethod.Get, "http://example.org/foo");
            var expectedAuthResult = MockAuthResult.GetAuthenticationResult(scopes);
            var mockAuthResult = MockAuthResult.GetAuthenticationResult(scopes);

            mockClientApplicationBase.Setup(pca => pca.GetAccountsAsync())
            .Returns(Task.FromResult(new List<IAccount>().AsEnumerable()));

            mockClientApplicationBase.Setup(pca => pca.AcquireTokenByUsernamePasswordAsync(scopes, mockUserAccounts.FirstOrDefault().Username, securePassword))
            .Returns(Task.FromResult(expectedAuthResult));

            usernamePasswordProvider.ClientApplication = mockClientApplicationBase.Object;
            await usernamePasswordProvider.AuthenticateRequestAsync(httpRequestMessage);

            Assert.IsInstanceOfType(usernamePasswordProvider, typeof(IAuthenticationProvider));
            Assert.IsInstanceOfType(usernamePasswordProvider.ClientApplication, typeof(IPublicClientApplication));
            Assert.IsNotNull(httpRequestMessage.Headers.Authorization);
            Assert.AreEqual(httpRequestMessage.Headers.Authorization.Scheme, CoreConstants.Headers.Bearer);
            Assert.AreEqual(httpRequestMessage.Headers.Authorization.Parameter, expectedAuthResult.AccessToken);
        }

        [TestMethod]
        public async Task UsernamePasswordProvider_WithUserAccountInCache()
        {
            var httpRequestMessage = new HttpRequestMessage(HttpMethod.Post, "http://example.org/foo");

            await usernamePasswordProvider.AuthenticateRequestAsync(httpRequestMessage);

            Assert.IsInstanceOfType(usernamePasswordProvider, typeof(IAuthenticationProvider));
            Assert.IsInstanceOfType(usernamePasswordProvider.ClientApplication, typeof(IPublicClientApplication));
            Assert.IsNotNull(httpRequestMessage.Headers.Authorization);
            Assert.AreEqual(httpRequestMessage.Headers.Authorization.Scheme, CoreConstants.Headers.Bearer);
            Assert.AreEqual(httpRequestMessage.Headers.Authorization.Parameter, mockAuthResult.AccessToken);
        }

        private SecureString GetSecureString(string strValue)
        {
            var secureString = new SecureString();
            foreach (char charItem in strValue.ToCharArray())
            {
                secureString.AppendChar(charItem);
            }

            return secureString;
        }
    }
}
