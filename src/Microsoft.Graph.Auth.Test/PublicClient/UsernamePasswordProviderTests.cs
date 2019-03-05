namespace Microsoft.Graph.Auth.Test.PublicClient
{
    using Microsoft.Graph.Auth.Test.Mocks;
    using Microsoft.Identity.Client;
    using Microsoft.VisualStudio.TestTools.UnitTesting;
    using Moq;
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Net.Http;
    using System.Security;
    using System.Threading.Tasks;

    [TestClass]
    public class UsernamePasswordProviderTests
    {
        private const string _clientId = "client_id";
        private string[] _scopes = new string[] { "User.Read" };
        private const string _organizationsAuthority = "https://login.microsoftonline.com/organizations/";
        private AuthenticationResult _silentAuthResult;
        private MockPublicClientApplication _mockClientApplicationBase;
        private GraphUserAccount _graphUserAccount;

        [TestInitialize]
        public void Setup()
        {
            _graphUserAccount = new GraphUserAccount
            {
                Email = "xyz@test.net",
                Environment = "login.microsoftonline.com",
                ObjectId = Guid.NewGuid().ToString(),
                TenantId = Guid.NewGuid().ToString()
            };
            _silentAuthResult = MockAuthResult.GetAuthenticationResult(new GraphAccount(_graphUserAccount), _scopes);
            _mockClientApplicationBase = new MockPublicClientApplication(_scopes, _organizationsAuthority, false, _clientId, _silentAuthResult);
        }

        [TestMethod]
        public void UsernamePasswordProvider_ShouldConstructAuthProviderWithPublicClientApp()
        {
            PublicClientApplication pca = new PublicClientApplication(_clientId, _organizationsAuthority, new TokenCache());
            UsernamePasswordProvider auth = new UsernamePasswordProvider(pca, _scopes);

            Assert.IsInstanceOfType(auth, typeof(IAuthenticationProvider), "Unexpected auth provider set.");
            Assert.IsNotNull(auth.ClientApplication, "Client application not initialized.");
            Assert.AreSame(pca, auth.ClientApplication, "Wrong client application set.");
        }

        [TestMethod]
        public void UsernamePasswordProvider_ConstructorShouldThrowExceptionWithNullPublicClientApp()
        {
            GraphAuthException ex = Assert.ThrowsException<GraphAuthException>(() => new UsernamePasswordProvider(null, _scopes));

            Assert.AreEqual(ex.Error.Code, ErrorConstants.Codes.InvalidRequest, "Invalid exception code.");
            Assert.AreEqual(ex.Error.Message, string.Format(ErrorConstants.Message.NullValue, "publicClientApplication"), "Invalid exception message.");
        }

        [TestMethod]
        public void UsernamePasswordProvider_ShouldCreatePublicClientApplicationWithMandatoryParams()
        {
            IClientApplicationBase clientApp = UsernamePasswordProvider.CreateClientApplication(_clientId);

            Assert.IsInstanceOfType(clientApp, typeof(PublicClientApplication), "Unexpected client application set.");
            Assert.AreEqual(_clientId, clientApp.ClientId, "Wrong client id set.");
            Assert.AreEqual(string.Format(AuthConstants.CloudList[NationalCloud.Global], AuthConstants.Tenants.Organizations), clientApp.Authority, "Wrong authority set.");
        }

        [TestMethod]
        public void UsernamePasswordProvider_ShouldCreatePublicClientApplicationForConfiguredCloud()
        {
            string testTenant = "infotest";
            IClientApplicationBase clientApp = UsernamePasswordProvider.CreateClientApplication(_clientId, null, testTenant, NationalCloud.China);

            Assert.IsInstanceOfType(clientApp, typeof(PublicClientApplication), "Unexpected client application set.");
            Assert.AreEqual(_clientId, clientApp.ClientId, "Wrong client id set.");
            Assert.AreEqual(string.Format(AuthConstants.CloudList[NationalCloud.China], testTenant), clientApp.Authority, "Wrong authority set.");
        }

        [TestMethod]
        public async Task UsernamePasswordProvider_ShouldGetNewAccessTokenWithNoIAccount()
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
                                UserAccount = new GraphUserAccount
                                {
                                    Email = "test@foo.bar"
                                },
                                Password = "very_complex"
                            }
                        }
                    }
                }
            });

            AuthenticationResult newAuthResult = MockAuthResult.GetAuthenticationResult();
            _mockClientApplicationBase.Setup((pca) => pca.AcquireTokenByUsernamePasswordAsync(_scopes, "test@foo.bar", It.IsAny<SecureString>()))
                .ReturnsAsync(newAuthResult);

            UsernamePasswordProvider authProvider = new UsernamePasswordProvider(_mockClientApplicationBase.Object, _scopes);
            await authProvider.AuthenticateRequestAsync(httpRequestMessage);

            Assert.IsInstanceOfType(authProvider.ClientApplication, typeof(IPublicClientApplication), "Unexpected client application set.");
            Assert.IsNotNull(httpRequestMessage.Headers.Authorization, "Unexpected auhtorization header set.");
            Assert.AreEqual(newAuthResult.AccessToken, httpRequestMessage.Headers.Authorization.Parameter, "Unexpected access token set.");
        }

        [TestMethod]
        public async Task UsernamePasswordProvider_ShouldGetAccessTokenForRequestIAccount()
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
            _mockClientApplicationBase.Setup((pca) => pca.AcquireTokenByUsernamePasswordAsync(_scopes, string.Empty, It.IsAny<SecureString>()))
                .ReturnsAsync(newAuthResult);

            UsernamePasswordProvider authProvider = new UsernamePasswordProvider(_mockClientApplicationBase.Object, _scopes);
            await authProvider.AuthenticateRequestAsync(httpRequestMessage);

            Assert.IsInstanceOfType(authProvider.ClientApplication, typeof(IPublicClientApplication), "Unexpected client application set.");
            Assert.IsNotNull(httpRequestMessage.Headers.Authorization, "Unexpected auhtorization header set.");
            Assert.AreEqual(_silentAuthResult.AccessToken, httpRequestMessage.Headers.Authorization.Parameter, "Unexpected access token set.");
        }
    }
}
