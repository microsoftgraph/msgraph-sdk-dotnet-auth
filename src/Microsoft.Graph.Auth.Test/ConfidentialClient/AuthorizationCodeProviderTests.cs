namespace Microsoft.Graph.Auth.Test.ConfidentialClient
{
    using Microsoft.Graph.Auth.Test.Mocks;
    using Microsoft.Identity.Client;
    using Microsoft.VisualStudio.TestTools.UnitTesting;
    using Moq;
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Net.Http;
    using System.Threading.Tasks;

    [TestClass]
    public class AuthorizationCodeProviderTests
    {
        private const string _clientId = "client_id";
        private const string _redirectUri = "redirect_uri";
        private string[] _scopes = new string[] { "User.Read" };
        private ClientCredential _clientCredential;
        private GraphUserAccount _graphUserAccount;
        private AuthenticationResult _mockAuthResult;
        private MockConfidentialClientApplication _mockClientApplicationBase;

        [TestInitialize]
        public void Setup()
        {
            _clientCredential = new ClientCredential("app_secret");
            _graphUserAccount = new GraphUserAccount
            {
                Email = "xyz@test.net",
                Environment = "login.microsoftonline.com",
                ObjectId = Guid.NewGuid().ToString(),
                TenantId = Guid.NewGuid().ToString()
            };
            _mockAuthResult = MockAuthResult.GetAuthenticationResult(new GraphAccount(_graphUserAccount), _scopes);
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
            AuthenticationException ex = Assert.ThrowsException<AuthenticationException>(() => new AuthorizationCodeProvider(null, _scopes));

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
        public void AuthorizationCodeProvider_ShouldCreateConfidentialClientApplicationForConfiguredNationalCloud()
        {
            string tenant = "infotest";
            IClientApplicationBase clientApp = AuthorizationCodeProvider.CreateClientApplication(_clientId, _redirectUri, _clientCredential, null, tenant, NationalCloud.China);

            Assert.IsInstanceOfType(clientApp, typeof(ConfidentialClientApplication), "Unexpected client application set.");
            Assert.AreEqual(_clientId, clientApp.ClientId, "Wrong client id set.");
            Assert.AreEqual(string.Format(AuthConstants.CloudList[NationalCloud.China], tenant), clientApp.Authority, "Wrong authority set.");
        }

        [TestMethod]
        public async Task AuthorizationCodeProvider_ShouldThrowChallangeRequiredExceptionWhenNoUserAccountIsNull()
        {
            HttpRequestMessage httpRequestMessage = new HttpRequestMessage(HttpMethod.Get, "http://example.org/foo");
            AuthorizationCodeProvider authCodeFlowProvider = new AuthorizationCodeProvider(_mockClientApplicationBase.Object, _scopes);

            AuthenticationException ex = await Assert.ThrowsExceptionAsync<AuthenticationException>(async () => await authCodeFlowProvider.AuthenticateRequestAsync(httpRequestMessage));

            Assert.AreEqual(ex.Error.Message, ErrorConstants.Message.AuthenticationChallengeRequired, "Invalid exception message.");
            Assert.IsInstanceOfType(authCodeFlowProvider.ClientApplication, typeof(IConfidentialClientApplication), "Unexpected client application set.");
            Assert.IsNull(httpRequestMessage.Headers.Authorization, "Unexpected auhtorization header set.");
        }

        [TestMethod]
        public async Task AuthorizationCodeProvider_ShouldGetCachedAccessTokenForRequestUserAccount()
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
                            AuthenticationProviderOption = new MsalAuthenticationProviderOption
                            {
                                UserAccount = _graphUserAccount
                            }
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

        [TestMethod]
        public async Task AuthorizationCodeProvider_ShouldGetTokenFromAuthorizationCode()
        {
            var newAuthResult = MockAuthResult.GetAuthenticationResult(null, _scopes);

            string authCode = "Auth_Code";
            _mockClientApplicationBase.Setup(cca => cca.AcquireTokenByAuthorizationCodeAsync(authCode, _scopes))
                .ReturnsAsync(newAuthResult);
            AuthorizationCodeProvider authCodeFlowProvider = new AuthorizationCodeProvider(_mockClientApplicationBase.Object, _scopes);

            var authResult = await authCodeFlowProvider.GetTokenByAuthorizationCodeAsync(authCode);

            Assert.IsInstanceOfType(authCodeFlowProvider.ClientApplication, typeof(IConfidentialClientApplication), "Unexpected client application set.");
            Assert.AreSame(newAuthResult.Scopes, authResult.Scopes, "Unexpected scopes set.");
        }
    }
}