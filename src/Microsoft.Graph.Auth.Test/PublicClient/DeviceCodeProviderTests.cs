namespace Microsoft.Graph.Auth.Test.PublicClient
{
    using System.Collections.Generic;
    using System.Linq;
    using System.Net.Http;
    using System.Threading;
    using System.Threading.Tasks;
    using Microsoft.Graph.Auth.Test.Mocks;
    using Microsoft.Identity.Client;
    using Microsoft.VisualStudio.TestTools.UnitTesting;

    [TestClass]
    public class DeviceCodeProviderTests
    {
        private MockPublicClientApplication mockClientApplicationBase;
        private IEnumerable<MockUserAccount> mockUserAccounts;
        private AuthenticationResult mockAuthResult;
        private DeviceCodeProvider deviceCodeFlowProvider;
        private const string clientId = "client-id";
        private const string redirectUri = "redirectUri";
        private const string appSecret = "appSecret";
        private string[] scopes = new string[] { "User.Read" };
        private string organizationsAuthority = "https://login.microsoftonline.com/organizations/";

        [TestInitialize]
        public void Setup()
        {
            mockUserAccounts = new List<MockUserAccount> {
                new MockUserAccount("xyz@test.net", "login.microsoftonline.com")
            };
            mockAuthResult = MockAuthResult.GetAuthenticationResult(scopes);
            mockClientApplicationBase = new MockPublicClientApplication(scopes, mockUserAccounts, organizationsAuthority, false, clientId, mockAuthResult);
            deviceCodeFlowProvider = new DeviceCodeProvider(mockClientApplicationBase.Object, scopes, DeviceCodeCallback);
        }

        [TestMethod]
        public void DeviceCodeProvider_DefaultConstructor()
        {
            Assert.IsInstanceOfType(deviceCodeFlowProvider, typeof(IAuthenticationProvider));
            Assert.IsNotNull(deviceCodeFlowProvider.ClientApplication);
            Assert.IsInstanceOfType(deviceCodeFlowProvider.ClientApplication, typeof(IPublicClientApplication));
            Assert.AreEqual(deviceCodeFlowProvider.ClientApplication.ClientId, clientId);
            Assert.AreEqual(deviceCodeFlowProvider.ClientApplication.Authority, organizationsAuthority);
        }

        [TestMethod]
        public async Task DeviceCodeProvider_WithNoUserAccountInCache()
        {
            var httpRequestMessage = new HttpRequestMessage(HttpMethod.Get, "http://example.org/foo");
            var expectedAuthResult = MockAuthResult.GetAuthenticationResult(scopes);

            mockClientApplicationBase.Setup(pca => pca.GetAccountsAsync())
                .Returns(Task.FromResult(new List<IAccount>().AsEnumerable()));
            mockClientApplicationBase.Setup(pca => pca.AcquireTokenWithDeviceCodeAsync(scopes, null, DeviceCodeCallback, CancellationToken.None))
                .Returns(Task.FromResult(expectedAuthResult));

            deviceCodeFlowProvider.ClientApplication = mockClientApplicationBase.Object;

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

            await deviceCodeFlowProvider.AuthenticateRequestAsync(httpRequestMessage);

            Assert.IsInstanceOfType(deviceCodeFlowProvider, typeof(IAuthenticationProvider));
            Assert.IsInstanceOfType(deviceCodeFlowProvider.ClientApplication, typeof(IPublicClientApplication));
            Assert.IsNotNull(httpRequestMessage.Headers.Authorization);
            Assert.AreEqual(httpRequestMessage.Headers.Authorization.Scheme, CoreConstants.Headers.Bearer);
            Assert.AreEqual(httpRequestMessage.Headers.Authorization.Parameter, mockAuthResult.AccessToken);
        }

        private async Task DeviceCodeCallback(DeviceCodeResult codeResult)
        {
            await Task.FromResult(0);
        }
    }
    
}
