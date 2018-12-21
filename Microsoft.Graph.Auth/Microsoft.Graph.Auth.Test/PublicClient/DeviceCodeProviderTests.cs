using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Graph.Auth.Test.Mocks;
using Microsoft.Identity.Client;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using NSubstitute;

namespace Microsoft.Graph.Auth.Test.PublicClient
{
    [TestClass]
    public class DeviceCodeProviderTests
    {
        private TokenCache tokenCache;
        private DeviceCodeProvider deviceCodeFlowProvider;
        private IPublicClientApplication publicClientAppMock;
        private const string clientId = "client-id";
        private string[] scopes = new string[] { "User.Read" };
        private MockUserAccount mockUserAccount, mockUserAccount2;

        [TestInitialize]
        public void Setup()
        {
            mockUserAccount = new MockUserAccount("xyz@test.net", "login.microsoftonline.com");
            mockUserAccount2 = new MockUserAccount("abc@test.com", "login.microsoftonline.com");
            publicClientAppMock = Substitute.For<IPublicClientApplication>();
            tokenCache = new TokenCache();
            deviceCodeFlowProvider = new DeviceCodeProvider(clientId, scopes, DeviceCodeCallback);
        }

        [TestMethod]
        public void DeviceCodeProvider_ConstructorWithNullNationalCloudAndTenant()
        {
            Assert.IsInstanceOfType(deviceCodeFlowProvider, typeof(IAuthenticationProvider));
            Assert.IsNotNull(deviceCodeFlowProvider.ClientApplication);
            Assert.IsInstanceOfType(deviceCodeFlowProvider.ClientApplication, typeof(IPublicClientApplication));
            Assert.AreEqual(deviceCodeFlowProvider.ClientApplication.ClientId, clientId);
            Assert.AreEqual(deviceCodeFlowProvider.ClientApplication.Authority, "https://login.microsoftonline.com/organizations/");
        }

        [TestMethod]
        public void DeviceCodeProvider_ConstructorWithNationalCloudAndNullTenant()
        {
            var authProvider = new DeviceCodeProvider(clientId, scopes, DeviceCodeCallback, NationalCloud.Germany);

            Assert.IsInstanceOfType(authProvider, typeof(IAuthenticationProvider));
            Assert.IsNotNull(authProvider.ClientApplication);
            Assert.IsInstanceOfType(authProvider.ClientApplication, typeof(IPublicClientApplication));
            Assert.AreEqual(authProvider.ClientApplication.ClientId, clientId);
            Assert.AreEqual(authProvider.ClientApplication.Authority, "https://login.microsoftonline.de/organizations/");
        }

        [TestMethod]
        public void DeviceCodeProvider_ConstructorWithPublicClientApplication()
        {
            var publicClient = new PublicClientApplication(clientId);
            var authProvider = new DeviceCodeProvider(publicClient, scopes, DeviceCodeCallback);

            Assert.IsInstanceOfType(authProvider, typeof(IAuthenticationProvider));
            Assert.IsNotNull(authProvider.ClientApplication);
            Assert.IsInstanceOfType(authProvider.ClientApplication, typeof(IPublicClientApplication));
            Assert.AreEqual(deviceCodeFlowProvider.ClientApplication.ClientId, clientId);
            Assert.AreEqual(deviceCodeFlowProvider.ClientApplication.Authority, "https://login.microsoftonline.com/organizations/");
        }

        [TestMethod]
        public async Task DeviceCodeProvider_WithNoUserAccountInCache()
        {
            var httpRequestMessage = new HttpRequestMessage(HttpMethod.Get, "http://example.org/foo");
            var expectedAuthResult = MockAuthResult.GetAuthenticationResult(scopes);

            publicClientAppMock.GetAccountsAsync().ReturnsForAnyArgs(new List<IAccount>());
            publicClientAppMock.AcquireTokenWithDeviceCodeAsync(scopes, string.Empty, null, new CancellationToken()).ReturnsForAnyArgs(expectedAuthResult);

            deviceCodeFlowProvider.ClientApplication = publicClientAppMock;

            await deviceCodeFlowProvider.AuthenticateRequestAsync(httpRequestMessage);

            Assert.IsInstanceOfType(deviceCodeFlowProvider, typeof(IAuthenticationProvider));
            Assert.IsInstanceOfType(deviceCodeFlowProvider.ClientApplication, typeof(IPublicClientApplication));
            Assert.IsNotNull(httpRequestMessage.Headers.Authorization);
            Assert.AreEqual(httpRequestMessage.Headers.Authorization.Scheme, CoreConstants.Headers.Bearer);
            Assert.AreEqual(httpRequestMessage.Headers.Authorization.Parameter, expectedAuthResult.AccessToken);
        }

        [TestMethod]
        public async Task DeviceCodeProvider_WithUserAccountInCache()
        {
            var httpRequestMessage = new HttpRequestMessage(HttpMethod.Get, "http://example.org/foo");
            var expectedAuthResult = MockAuthResult.GetAuthenticationResult(scopes);
            var mockAuthResult = MockAuthResult.GetAuthenticationResult(scopes);

            publicClientAppMock.GetAccountsAsync().ReturnsForAnyArgs(new List<IAccount> { mockUserAccount });
            publicClientAppMock.AcquireTokenSilentAsync(scopes, null).ReturnsForAnyArgs(expectedAuthResult);
            publicClientAppMock.AcquireTokenWithDeviceCodeAsync(scopes, string.Empty, null, CancellationToken.None).ReturnsForAnyArgs(mockAuthResult);

            deviceCodeFlowProvider.ClientApplication = publicClientAppMock;

            await deviceCodeFlowProvider.AuthenticateRequestAsync(httpRequestMessage);

            Assert.IsInstanceOfType(deviceCodeFlowProvider, typeof(IAuthenticationProvider));
            Assert.IsInstanceOfType(deviceCodeFlowProvider.ClientApplication, typeof(IPublicClientApplication));
            Assert.IsNotNull(httpRequestMessage.Headers.Authorization);
            Assert.AreEqual(httpRequestMessage.Headers.Authorization.Scheme, CoreConstants.Headers.Bearer);
            Assert.AreEqual(httpRequestMessage.Headers.Authorization.Parameter, expectedAuthResult.AccessToken);
        }

        private async Task DeviceCodeCallback(DeviceCodeResult codeResult)
        {
            await Task.FromResult(0);
        }
    }
    
}
