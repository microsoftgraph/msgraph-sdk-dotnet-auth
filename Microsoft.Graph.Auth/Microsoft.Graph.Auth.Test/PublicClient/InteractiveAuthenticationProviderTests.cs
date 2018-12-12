using Microsoft.Graph.Auth.Test.Mocks;
using Microsoft.Identity.Client;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using NSubstitute;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;

namespace Microsoft.Graph.Auth.Test.PublicClient
{
    [TestClass]
    public class InteractiveAuthenticationProviderTests
    {
        private TokenCache tokenCache;
        private InteractiveAuthenticationProvider interactiveFlowProvider;
        private IPublicClientApplication publicClientAppMock;
        private string clientId = "client-id";
        private string commonAuthority = "https://login.microsoftonline.com/common/";
        private readonly string[] scopes = new string[] { "User.Read" };
        private MockUserAccount mockUserAccount, mockUserAccount2;

        [TestInitialize]
        public void Setup()
        {
            mockUserAccount = new MockUserAccount("xyz@test.net", "login.microsoftonline.com");
            mockUserAccount2 = new MockUserAccount("abc@test.com", "login.microsoftonline.com");
            tokenCache = new TokenCache();
            interactiveFlowProvider = new InteractiveAuthenticationProvider(clientId, scopes);
        }

        [TestMethod]
        public void InteractiveAuthenticationProvider_ConstructorWithNullableParams()
        {
            Assert.IsInstanceOfType(interactiveFlowProvider, typeof(IAuthenticationProvider));
            Assert.IsNotNull(interactiveFlowProvider.ClientApplication);
            Assert.IsInstanceOfType(interactiveFlowProvider.ClientApplication, typeof(IPublicClientApplication));
        }

        [TestMethod]
        public void InteractiveAuthenticationProvider_ConstructorWithoutNullableParams()
        {
            var authProvider = new InteractiveAuthenticationProvider(clientId, scopes, mockUserAccount, commonAuthority, tokenCache, UIBehavior.SelectAccount, "extra", null, new UIParent());

            Assert.IsInstanceOfType(authProvider, typeof(IAuthenticationProvider));
            Assert.IsNotNull(authProvider.ClientApplication);
            Assert.IsInstanceOfType(authProvider.ClientApplication, typeof(IPublicClientApplication));
        }

        [TestMethod]
        public async Task InteractiveAuthenticationProvider_WithNoUserAccountInCache()
        {
            var httpRequestMessage = new HttpRequestMessage(HttpMethod.Get, "http://example.org/foo");
            var expectedAuthResult = MockAuthResult.GetAuthenticationResult(scopes);
            var mockAuthResult = MockAuthResult.GetAuthenticationResult(scopes);

            publicClientAppMock = Substitute.For<IPublicClientApplication>();
            publicClientAppMock.GetAccountsAsync().ReturnsForAnyArgs(new List<IAccount>());
            publicClientAppMock.AcquireTokenAsync(scopes, string.Empty, UIBehavior.SelectAccount, null, null, null, null).ReturnsForAnyArgs(expectedAuthResult);
            publicClientAppMock.AcquireTokenAsync(scopes, mockUserAccount, UIBehavior.SelectAccount, null, null, null, null).ReturnsForAnyArgs(mockAuthResult);

            interactiveFlowProvider.ClientApplication = publicClientAppMock;
            await interactiveFlowProvider.AuthenticateRequestAsync(httpRequestMessage);

            Assert.IsInstanceOfType(interactiveFlowProvider, typeof(IAuthenticationProvider));
            Assert.IsInstanceOfType(interactiveFlowProvider.ClientApplication, typeof(IPublicClientApplication));
            Assert.IsNotNull(httpRequestMessage.Headers.Authorization);
            Assert.AreEqual(httpRequestMessage.Headers.Authorization.Scheme, CoreConstants.Headers.Bearer);
            Assert.AreEqual(httpRequestMessage.Headers.Authorization.Parameter, expectedAuthResult.AccessToken);
        }

        [TestMethod]
        public async Task InteractiveAuthenticationProvider_WithUserAccountInCache()
        {
            var httpRequestMessage = new HttpRequestMessage(HttpMethod.Post, "http://example.org/foo");
            var expectedAuthResult = MockAuthResult.GetAuthenticationResult(scopes);
            var mockAuthResult = MockAuthResult.GetAuthenticationResult(scopes);

            publicClientAppMock = Substitute.For<IPublicClientApplication>();
            publicClientAppMock.GetAccountsAsync().ReturnsForAnyArgs(new List<IAccount> { mockUserAccount });
            publicClientAppMock.AcquireTokenSilentAsync(scopes, mockUserAccount).ReturnsForAnyArgs(expectedAuthResult);
            publicClientAppMock.AcquireTokenAsync(scopes, mockUserAccount, UIBehavior.SelectAccount, null, null, null, null).Returns(mockAuthResult);

            interactiveFlowProvider.ClientApplication = publicClientAppMock;
            await interactiveFlowProvider.AuthenticateRequestAsync(httpRequestMessage);

            Assert.IsInstanceOfType(interactiveFlowProvider, typeof(IAuthenticationProvider));
            Assert.IsInstanceOfType(interactiveFlowProvider.ClientApplication, typeof(IPublicClientApplication));
            Assert.IsNotNull(httpRequestMessage.Headers.Authorization);
            Assert.AreEqual(httpRequestMessage.Headers.Authorization.Scheme, CoreConstants.Headers.Bearer);
            Assert.AreEqual(httpRequestMessage.Headers.Authorization.Parameter, expectedAuthResult.AccessToken);
        }
    }
}
