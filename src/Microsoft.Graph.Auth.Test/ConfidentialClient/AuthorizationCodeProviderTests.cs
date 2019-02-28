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
        private const string _clientId = "client_id";
        private const string _redirectUri = "redirectUri";
        private string[] _scopes = new string[] { "User.Read" };
        private AuthenticationResult _mockAuthResult;
        private MockConfidentialClientApplication _mockClientApplicationBase;
        private GraphUserAccount _graphUserAccount;
        private ClientCredential _clientCredential;

        [TestInitialize]
        public void Setup()
        {
            _clientCredential = new ClientCredential("appSecret");
            _mockAuthResult = MockAuthResult.GetAuthenticationResult(_scopes);
            _graphUserAccount = new GraphUserAccount
            {
                Email = "xyz@test.net",
                Environment = "login.microsoftonline.com",
                ObjectId = Guid.NewGuid().ToString(),
                TenantId = Guid.NewGuid().ToString()
            };
            _mockClientApplicationBase = new MockConfidentialClientApplication(_scopes, "common", false, _clientId, _mockAuthResult);
        }

        [TestMethod]
        public void AuthorizationCodeProvider_ShouldConstructAuthProviderWithConfidentialClientApp()
        {
            ConfidentialClientApplication cca = new ConfidentialClientApplication(_clientId, _redirectUri, _clientCredential, new TokenCache(), null);
            AuthorizationCodeProvider auth = new AuthorizationCodeProvider(cca, _scopes);

            Assert.IsInstanceOfType(auth, typeof(IAuthenticationProvider), "Unexpected auth provider set.");
            Assert.IsNotNull(auth.ClientApplication, "Client application not initialized.");
            Assert.AreSame(cca, auth.ClientApplication, "Wrong client application set.");
        }

        [TestMethod]
        public void AuthorizationCodeProvider_ConstructorShouldThrowExceptionWithNullConfidentialClientApp()
        {
            GraphAuthException ex = Assert.ThrowsException<GraphAuthException>(() => new AuthorizationCodeProvider(null, _scopes));

            Assert.AreEqual(ex.Error.Code, ErrorConstants.Codes.InvalidRequest, "Invalid exception code.");
            Assert.AreEqual(ex.Error.Message, string.Format(ErrorConstants.Message.NullValue, "confidentialClientApplication"), "Invalid exception message.");
        }

        [TestMethod]
        public void AuthorizationCodeProvider_ShouldCreateConfidentialClientApplicationWithMandatoryParams()
        {
            IClientApplicationBase clientApp = AuthorizationCodeProvider.CreateClientApplication(_clientId, _redirectUri, _clientCredential);

            Assert.IsInstanceOfType(clientApp, typeof(ConfidentialClientApplication), "Unexpected client application set.");
            Assert.AreEqual(_clientId, clientApp.ClientId, "Wrong client id set.");
            Assert.AreEqual(string.Format(AuthConstants.CloudList[NationalCloud.Global], AuthConstants.Tenants.Common), clientApp.Authority, "Wrong authority set.");
        }

        [TestMethod]
        public void AuthorizationCodeProvider_ShouldCreateConfidentialClientApplicationForConfiguredCloud()
        {
            string testTenant = "infotest";
            IClientApplicationBase clientApp = AuthorizationCodeProvider.CreateClientApplication(_clientId, _redirectUri, _clientCredential, null, testTenant, NationalCloud.China);

            Assert.IsInstanceOfType(clientApp, typeof(ConfidentialClientApplication), "Unexpected client application set.");
            Assert.AreEqual(_clientId, clientApp.ClientId, "Wrong client id set.");
            Assert.AreEqual(string.Format(AuthConstants.CloudList[NationalCloud.China], testTenant), clientApp.Authority, "Wrong authority set.");
        }

        [TestMethod]
        public async Task AuthorizationCodeProvider_ShouldThrowChallangeRequiredExceptionWithNoIAccount()
        {
            HttpRequestMessage httpRequestMessage = new HttpRequestMessage(HttpMethod.Get, "http://example.org/foo");
            AuthorizationCodeProvider authCodeFlowProvider = new AuthorizationCodeProvider(_mockClientApplicationBase.Object, _scopes);

            GraphAuthException ex = await Assert.ThrowsExceptionAsync<GraphAuthException>(async () => await authCodeFlowProvider.AuthenticateRequestAsync(httpRequestMessage));

            Assert.AreEqual(ex.Error.Message, ErrorConstants.Message.AuthenticationChallengeRequired, "Invalid exception message.");
            Assert.IsInstanceOfType(authCodeFlowProvider.ClientApplication, typeof(IConfidentialClientApplication), "Unexpected client application set.");
            Assert.IsNull(httpRequestMessage.Headers.Authorization, "Unexpected auhtorization header set.");
        }

        [TestMethod]
        public async Task AuthorizationCodeProvider_ShouldGetExistingAccessTokenForRequestIAccount()
        {
            var httpRequestMessage = new HttpRequestMessage(HttpMethod.Get, "http://example.org/foo");
            httpRequestMessage.Properties.Add(typeof(GraphRequestContext).ToString(), new GraphRequestContext
            {
                MiddlewareOptions = new Dictionary<string, IMiddlewareOption>
                {
                    {
                        typeof(AuthenticationHandlerOption).ToString(),
                        new AuthenticationHandlerOption
                        {
                            AuthenticationProviderOption = new MsalAuthProviderOption{ UserAccount = _graphUserAccount}
                        }
                    }
                }
            });

            AuthorizationCodeProvider authCodeFlowProvider = new AuthorizationCodeProvider(_mockClientApplicationBase.Object, _scopes);
            await authCodeFlowProvider.AuthenticateRequestAsync(httpRequestMessage);

            Assert.IsInstanceOfType(authCodeFlowProvider.ClientApplication, typeof(IConfidentialClientApplication), "Unexpected client application set.");
            Assert.IsNotNull(httpRequestMessage.Headers.Authorization, "Auhtorization header not set.");
            Assert.AreEqual(httpRequestMessage.Headers.Authorization.Scheme, CoreConstants.Headers.Bearer, "Unexpected auhtorization header scheme set.");
            Assert.AreEqual(httpRequestMessage.Headers.Authorization.Parameter, _mockAuthResult.AccessToken, "Unexpected auhtorization header parameter set.");
        }
    }
}