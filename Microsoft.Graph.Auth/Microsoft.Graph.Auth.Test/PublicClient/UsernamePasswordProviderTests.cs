using Microsoft.Graph.Auth.Test.Mocks;
using Microsoft.Identity.Client;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using NSubstitute;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Security;
using System.Text;
using System.Threading.Tasks;

namespace Microsoft.Graph.Auth.Test.PublicClient
{
    [TestClass]
    public class UsernamePasswordProviderTests
    {
        private MockTokenCacheProvider tokenCacheStorage;
        private UsernamePasswordProvider intergratedWindowsAuthFlowProvider;
        private IPublicClientApplication publicClientAppMock;
        private string clientId = "client-id";
        private string organizationsAuthority = "https://login.microsoftonline.com/organizations/";
        private string[] scopes = new string[] { "User.Read" };
        private MockUserAccount mockUserAccount, mockUserAccount2;
        private SecureString securePassword;

        [TestInitialize]
        public void Setup()
        {
            mockUserAccount = new MockUserAccount("xyz@test.net", "login.microsoftonline.com");
            mockUserAccount2 = new MockUserAccount("abc@test.com", "login.microsoftonline.com");
            securePassword = GetSecureString("veryGoodPassword");
            tokenCacheStorage = new MockTokenCacheProvider();
            intergratedWindowsAuthFlowProvider = new UsernamePasswordProvider(clientId, tokenCacheStorage, scopes, mockUserAccount.Username, securePassword);
        }

        [TestMethod]
        public void UsernamePasswordProvider_ConstructorWithNullableParams()
        {
            Assert.IsInstanceOfType(intergratedWindowsAuthFlowProvider, typeof(IAuthenticationProvider));
            Assert.IsNotNull(intergratedWindowsAuthFlowProvider.ClientApplication);
            Assert.IsInstanceOfType(intergratedWindowsAuthFlowProvider.ClientApplication, typeof(IPublicClientApplication));
            Assert.AreEqual(intergratedWindowsAuthFlowProvider.ClientApplication.ClientId, clientId);
            Assert.AreEqual(intergratedWindowsAuthFlowProvider.ClientApplication.Authority, "https://login.microsoftonline.com/organizations/");
        }

        [TestMethod]
        public void UsernamePasswordProvider_ConstructorWithoutNullableParams()
        {
            var authProvider = new UsernamePasswordProvider(clientId, scopes, mockUserAccount.Username, securePassword, NationalCloud.UsGovernment, "contoso");

            Assert.IsInstanceOfType(authProvider, typeof(IAuthenticationProvider));
            Assert.IsNotNull(authProvider.ClientApplication);
            Assert.IsInstanceOfType(authProvider.ClientApplication, typeof(IPublicClientApplication));
            Assert.AreEqual(authProvider.ClientApplication.ClientId, clientId);
            Assert.AreEqual(authProvider.ClientApplication.Authority, "https://login.microsoftonline.us/contoso/");
        }

        [TestMethod]
        public void UsernamePasswordProvider_ConstructorWithPublicClientApplication()
        {
            var publicClient = new PublicClientApplication(clientId);
            var authProvider = new UsernamePasswordProvider(publicClient, scopes, mockUserAccount.Username, securePassword);

            Assert.IsInstanceOfType(authProvider, typeof(IAuthenticationProvider));
            Assert.IsNotNull(authProvider.ClientApplication);
            Assert.IsInstanceOfType(authProvider.ClientApplication, typeof(IPublicClientApplication));
            Assert.AreEqual(authProvider.ClientApplication.ClientId, clientId);
            Assert.AreEqual(authProvider.ClientApplication.Authority, "https://login.microsoftonline.com/common/");
        }

        [TestMethod]
        public async Task UsernamePasswordProvider_WithNoUserAccountInCache()
        {
            var httpRequestMessage = new HttpRequestMessage(HttpMethod.Get, "http://example.org/foo");
            var expectedAuthResult = MockAuthResult.GetAuthenticationResult(scopes);
            var mockAuthResult = MockAuthResult.GetAuthenticationResult(scopes);

            publicClientAppMock = Substitute.For<IPublicClientApplication>();
            publicClientAppMock.GetAccountsAsync().ReturnsForAnyArgs(new List<IAccount>());
            publicClientAppMock.AcquireTokenSilentAsync(scopes, mockUserAccount).ReturnsForAnyArgs(mockAuthResult);
            publicClientAppMock.AcquireTokenByUsernamePasswordAsync(scopes, mockUserAccount.Username, securePassword).ReturnsForAnyArgs(expectedAuthResult);

            intergratedWindowsAuthFlowProvider.ClientApplication = publicClientAppMock;
            await intergratedWindowsAuthFlowProvider.AuthenticateRequestAsync(httpRequestMessage);

            Assert.IsInstanceOfType(intergratedWindowsAuthFlowProvider, typeof(IAuthenticationProvider));
            Assert.IsInstanceOfType(intergratedWindowsAuthFlowProvider.ClientApplication, typeof(IPublicClientApplication));
            Assert.IsNotNull(httpRequestMessage.Headers.Authorization);
            Assert.AreEqual(httpRequestMessage.Headers.Authorization.Scheme, CoreConstants.Headers.Bearer);
            Assert.AreEqual(httpRequestMessage.Headers.Authorization.Parameter, expectedAuthResult.AccessToken);
        }

        [TestMethod]
        public async Task UsernamePasswordProvider_WithUserAccountInCache()
        {
            var httpRequestMessage = new HttpRequestMessage(HttpMethod.Post, "http://example.org/foo");
            var expectedAuthResult = MockAuthResult.GetAuthenticationResult(scopes);
            var mockAuthResult = MockAuthResult.GetAuthenticationResult(scopes);

            publicClientAppMock = Substitute.For<IPublicClientApplication>();
            publicClientAppMock.GetAccountsAsync().ReturnsForAnyArgs(new List<IAccount> { mockUserAccount });
            publicClientAppMock.AcquireTokenSilentAsync(scopes, mockUserAccount).ReturnsForAnyArgs(expectedAuthResult);
            publicClientAppMock.AcquireTokenByUsernamePasswordAsync(scopes, mockUserAccount.Username, securePassword).ReturnsForAnyArgs(mockAuthResult);

            intergratedWindowsAuthFlowProvider.ClientApplication = publicClientAppMock;
            await intergratedWindowsAuthFlowProvider.AuthenticateRequestAsync(httpRequestMessage);

            Assert.IsInstanceOfType(intergratedWindowsAuthFlowProvider, typeof(IAuthenticationProvider));
            Assert.IsInstanceOfType(intergratedWindowsAuthFlowProvider.ClientApplication, typeof(IPublicClientApplication));
            Assert.IsNotNull(httpRequestMessage.Headers.Authorization);
            Assert.AreEqual(httpRequestMessage.Headers.Authorization.Scheme, CoreConstants.Headers.Bearer);
            Assert.AreEqual(httpRequestMessage.Headers.Authorization.Parameter, expectedAuthResult.AccessToken);
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
