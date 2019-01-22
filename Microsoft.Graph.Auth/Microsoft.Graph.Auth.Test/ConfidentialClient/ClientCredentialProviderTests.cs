using Microsoft.Graph.Auth.Test.Mocks;
using Microsoft.Identity.Client;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;

namespace Microsoft.Graph.Auth.Test.ConfidentialClient
{
    [TestClass]
    public class ClientCredentialProviderTests
    {
        private MockConfidentialClientApplication mockClientApplicationBase;
        private IEnumerable<MockUserAccount> mockUserAccounts;
        private AuthenticationResult mockAuthResult;
        private ClientCredentialProvider clientCredentialFlowProvider;
        private const string clientId = "client-id";
        private string[] scopes = new string[] { "https://graph.microsoft.com/.default" };
        private string commonAuthority = "https://login.microsoftonline.com/common/";

        [TestInitialize]
        public void Setup()
        {
            mockUserAccounts = new List<MockUserAccount> {
                new MockUserAccount("xyz@test.net", "login.microsoftonline.com")
            };
            mockAuthResult = MockAuthResult.GetAuthenticationResult(scopes);
            mockClientApplicationBase = new MockConfidentialClientApplication(scopes, mockUserAccounts, commonAuthority, false, clientId, mockAuthResult);
            clientCredentialFlowProvider = new ClientCredentialProvider(mockClientApplicationBase.Object, scopes);
        }

        [TestMethod]
        public void ClientCredentialProvider_DefaultConstructor()
        {
            Assert.IsInstanceOfType(clientCredentialFlowProvider, typeof(IAuthenticationProvider));
            Assert.IsNotNull(clientCredentialFlowProvider.ClientApplication);
            Assert.IsInstanceOfType(clientCredentialFlowProvider.ClientApplication, typeof(IConfidentialClientApplication));
            Assert.AreEqual(clientCredentialFlowProvider.ClientApplication.ClientId, clientId);
            Assert.AreEqual(clientCredentialFlowProvider.ClientApplication.Authority, commonAuthority);
        }

        [TestMethod]
        public async Task ClientCredentialProvider_WithNoUserAccountInCache()
        {
            var httpRequestMessage = new HttpRequestMessage(HttpMethod.Get, "http://example.org/foo");
            var expectedAuthResult = MockAuthResult.GetAuthenticationResult(scopes);
            var mockAuthResult = MockAuthResult.GetAuthenticationResult(scopes);

            mockClientApplicationBase.Setup(cca => cca.GetAccountsAsync())
            .Returns(Task.FromResult(new List<IAccount>().AsEnumerable()));

            mockClientApplicationBase.Setup(cca => cca.AcquireTokenForClientAsync(scopes, false))
            .Returns(Task.FromResult(expectedAuthResult));

            clientCredentialFlowProvider.ClientApplication = mockClientApplicationBase.Object;

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

            mockClientApplicationBase.Setup(cca => cca.AcquireTokenForClientAsync(scopes, false))
            .Returns(Task.FromResult(mockAuthResult));

            clientCredentialFlowProvider.ClientApplication = mockClientApplicationBase.Object;

            await clientCredentialFlowProvider.AuthenticateRequestAsync(httpRequestMessage);

            Assert.IsInstanceOfType(clientCredentialFlowProvider, typeof(IAuthenticationProvider));
            Assert.IsInstanceOfType(clientCredentialFlowProvider.ClientApplication, typeof(IConfidentialClientApplication));
            Assert.IsNotNull(httpRequestMessage.Headers.Authorization);
            Assert.AreEqual(httpRequestMessage.Headers.Authorization.Scheme, CoreConstants.Headers.Bearer);
            Assert.AreEqual(httpRequestMessage.Headers.Authorization.Parameter, mockAuthResult.AccessToken);
        }
    }
}
