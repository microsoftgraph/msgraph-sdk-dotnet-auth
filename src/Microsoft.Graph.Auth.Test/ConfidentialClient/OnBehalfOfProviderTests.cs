namespace Microsoft.Graph.Auth.Test.ConfidentialClient
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Net.Http;
    using System.Threading.Tasks;
    using Microsoft.Graph.Auth.Test.Mocks;
    using Microsoft.Identity.Client;
    using Microsoft.VisualStudio.TestTools.UnitTesting;
    using Moq;

    [TestClass]
    public class OnBehalfOfProviderTests
    {
        private const string _clientId = "client_id";
        private const string _redirectUri = "redirectUri";
        private string[] _scopes = new string[] { "User.Read" };
        private AuthenticationResult _silentAuthResult;
        private MockConfidentialClientApplication _mockClientApplicationBase;
        private GraphUserAccount _graphUserAccount;
        private ClientCredential _clientCredential;

        [TestInitialize]
        public void Setup()
        {
            _clientCredential = new ClientCredential("appSecret");
            _silentAuthResult = MockAuthResult.GetAuthenticationResult(_scopes);
            _graphUserAccount = new GraphUserAccount
            {
                Email = "xyz@test.net",
                Environment = "login.microsoftonline.com",
                ObjectId = Guid.NewGuid().ToString(),
                TenantId = Guid.NewGuid().ToString()
            };
            _mockClientApplicationBase = new MockConfidentialClientApplication(_scopes, "common", false, _clientId, _silentAuthResult);
        }

        [TestMethod]
        public void OnBehalfOfProvider_ShouldConstructAuthProviderWithConfidentialClientApp()
        {
            ConfidentialClientApplication cca = new ConfidentialClientApplication(_clientId, _redirectUri, _clientCredential, new TokenCache(), null);
            OnBehalfOfProvider auth = new OnBehalfOfProvider(cca, _scopes);

            Assert.IsInstanceOfType(auth, typeof(IAuthenticationProvider), "Unexpected auth provider set.");
            Assert.IsNotNull(auth.ClientApplication, "Client application not initialized.");
            Assert.AreSame(cca, auth.ClientApplication, "Wrong client application set.");
        }

        [TestMethod]
        public void OnBehalfOfProvider_ConstructorShouldThrowExceptionWithNullConfidentialClientApp()
        {
            GraphAuthException ex = Assert.ThrowsException<GraphAuthException>(() => new OnBehalfOfProvider(null, _scopes));

            Assert.AreEqual(ex.Error.Code, ErrorConstants.Codes.InvalidRequest, "Invalid exception code.");
            Assert.AreEqual(ex.Error.Message, string.Format(ErrorConstants.Message.NullValue, "confidentialClientApplication"), "Invalid exception message.");
        }

        [TestMethod]
        public void OnBehalfOfProvider_ShouldCreateConfidentialClientApplicationWithMandatoryParams()
        {
            IClientApplicationBase clientApp = OnBehalfOfProvider.CreateClientApplication(_clientId, _redirectUri, _clientCredential);

            Assert.IsInstanceOfType(clientApp, typeof(ConfidentialClientApplication), "Unexpected client application set.");
            Assert.AreEqual(_clientId, clientApp.ClientId, "Wrong client id set.");
            Assert.AreEqual(string.Format(AuthConstants.CloudList[NationalCloud.Global], AuthConstants.Tenants.Common), clientApp.Authority, "Wrong authority set.");
        }

        [TestMethod]
        public void OnBehalfOfProvider_ShouldCreateConfidentialClientApplicationForConfiguredCloud()
        {
            string testTenant = "infotest";
            IClientApplicationBase clientApp = OnBehalfOfProvider.CreateClientApplication(_clientId, _redirectUri, _clientCredential, null, testTenant, NationalCloud.China);

            Assert.IsInstanceOfType(clientApp, typeof(ConfidentialClientApplication), "Unexpected client application set.");
            Assert.AreEqual(_clientId, clientApp.ClientId, "Wrong client id set.");
            Assert.AreEqual(string.Format(AuthConstants.CloudList[NationalCloud.China], testTenant), clientApp.Authority, "Wrong authority set.");
        }

        [TestMethod]
        public async Task OnBehalfOfProvider_ShouldGetNewAccessTokenWithNoIAccount()
        {
            UserAssertion assertion = new UserAssertion("access_token");
            HttpRequestMessage httpRequestMessage = new HttpRequestMessage(HttpMethod.Get, "http://example.org/foo");
            httpRequestMessage.Properties.Add(typeof(GraphRequestContext).ToString(), new GraphRequestContext
            {
                MiddlewareOptions = new Dictionary<string, IMiddlewareOption>
                {
                    {
                        typeof(AuthenticationHandlerOption).ToString(),
                        new AuthenticationHandlerOption
                        {
                            AuthenticationProviderOption = new MsalAuthProviderOption
                            {
                                UserAssertion =  assertion
                            }
                        }
                    }
                }
            });

            AuthenticationResult expectedAuthResult = MockAuthResult.GetAuthenticationResult();
            _mockClientApplicationBase.Setup((cca) => cca.AcquireTokenOnBehalfOfAsync(_scopes, assertion, "common"))
                .ReturnsAsync(expectedAuthResult);

            OnBehalfOfProvider authProvider = new OnBehalfOfProvider(_mockClientApplicationBase.Object, _scopes);
            await authProvider.AuthenticateRequestAsync(httpRequestMessage);

            Assert.IsInstanceOfType(authProvider.ClientApplication, typeof(IConfidentialClientApplication), "Unexpected client application set.");
            Assert.IsNotNull(httpRequestMessage.Headers.Authorization, "Unexpected auhtorization header set.");
            Assert.AreEqual(expectedAuthResult.AccessToken, httpRequestMessage.Headers.Authorization.Parameter, "Unexpected access token set.");
        }

        [TestMethod]
        public async Task OnBehalfOfProvider_ShouldGetAccessTokenForRequestIAccount()
        {
            UserAssertion assertion = new UserAssertion("access_token");
            HttpRequestMessage httpRequestMessage = new HttpRequestMessage(HttpMethod.Get, "http://example.org/foo");
            httpRequestMessage.Properties.Add(typeof(GraphRequestContext).ToString(), new GraphRequestContext
            {
                MiddlewareOptions = new Dictionary<string, IMiddlewareOption>
                {
                    {
                        typeof(AuthenticationHandlerOption).ToString(),
                        new AuthenticationHandlerOption
                        {
                            AuthenticationProviderOption = new MsalAuthProviderOption
                            {
                                UserAssertion =  assertion,
                                UserAccount = _graphUserAccount
                            }
                        }
                    }
                }
            });

            AuthenticationResult newAuthResult = MockAuthResult.GetAuthenticationResult();
            _mockClientApplicationBase.Setup((cca) => cca.AcquireTokenOnBehalfOfAsync(_scopes, assertion, "common"))
                .ReturnsAsync(newAuthResult);

            OnBehalfOfProvider authProvider = new OnBehalfOfProvider(_mockClientApplicationBase.Object, _scopes);
            await authProvider.AuthenticateRequestAsync(httpRequestMessage);

            Assert.IsInstanceOfType(authProvider.ClientApplication, typeof(IConfidentialClientApplication), "Unexpected client application set.");
            Assert.IsNotNull(httpRequestMessage.Headers.Authorization, "Unexpected auhtorization header set.");
            Assert.AreEqual(_silentAuthResult.AccessToken, httpRequestMessage.Headers.Authorization.Parameter, "Unexpected access token set.");
        }
    }
}
