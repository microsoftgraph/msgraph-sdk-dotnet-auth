namespace Microsoft.Graph.Auth.Test.ConfidentialClient
{
    using Microsoft.Graph.Auth.Test.Mocks;
    using Microsoft.Identity.Client;
    using Microsoft.VisualStudio.TestTools.UnitTesting;
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Net.Http;
    using System.Threading.Tasks;

    [TestClass]
    public class AuthorizationCodeProviderTests
    {
        private AuthorizationCodeProvider authCodeFlowProvider;
        private List<MockUserAccount> mockUserAccounts;
        private AuthenticationResult mockAuthResult;
        private MockConfidentialClientApplication mockClientApplicationBase;
        private const string clientId = "client_id";
        private string[] scopes = new string[] { "User.Read" };
        private const string redirectUri = "redirectUri";
        private const string appSecret = "appSecret";

        [TestInitialize]
        public void Setup()
        {
            mockUserAccounts = new List<MockUserAccount> {
                new MockUserAccount("xyz@test.net", "login.microsoftonline.com")
            };
            mockAuthResult = MockAuthResult.GetAuthenticationResult(scopes);
            mockClientApplicationBase = new MockConfidentialClientApplication(scopes, mockUserAccounts, "common", false, clientId, mockAuthResult);
            authCodeFlowProvider = new AuthorizationCodeProvider(mockClientApplicationBase.Object, scopes);
        }

        [TestMethod]
        public void AuthorizationCodeProvider_DefaultConstructor()
        {
            Assert.IsInstanceOfType(authCodeFlowProvider, typeof(IAuthenticationProvider));
            Assert.IsNotNull(authCodeFlowProvider.ClientApplication);
        }

        [TestMethod]
        public async Task AuthorizationCodeProvider_WithNoUserAccountInCache()
        {
            var httpRequestMessage = new HttpRequestMessage(HttpMethod.Get, "http://example.org/foo");
            var expectedAuthResult = MockAuthResult.GetAuthenticationResult(scopes);

            mockClientApplicationBase.Setup(
                cca => cca.GetAccountsAsync())
                .Returns(Task.FromResult(new List<IAccount>().AsEnumerable()));

            authCodeFlowProvider.ClientApplication = mockClientApplicationBase.Object;

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

            await authCodeFlowProvider.AuthenticateRequestAsync(httpRequestMessage);

            Assert.IsInstanceOfType(authCodeFlowProvider, typeof(IAuthenticationProvider));
            Assert.IsInstanceOfType(authCodeFlowProvider.ClientApplication, typeof(IConfidentialClientApplication));
            Assert.IsNotNull(httpRequestMessage.Headers.Authorization);
            Assert.AreEqual(httpRequestMessage.Headers.Authorization.Scheme, CoreConstants.Headers.Bearer);
            Assert.AreEqual(httpRequestMessage.Headers.Authorization.Parameter, mockAuthResult.AccessToken);
        }
    }
}