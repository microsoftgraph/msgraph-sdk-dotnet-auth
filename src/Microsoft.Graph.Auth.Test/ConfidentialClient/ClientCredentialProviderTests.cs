using Microsoft.Graph.Auth.Test.Mocks;
using Microsoft.Identity.Client;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
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
        private const string _clientId = "client_id";
        private const string _redirectUri = "redirectUri";
        private const string _commonAuthority = "https://login.microsoftonline.com/common/";

        private AuthenticationResult _mockAuthResult;
        private MockConfidentialClientApplication _mockClientApplicationBase;
        private ClientCredential _clientCredential;

        [TestInitialize]
        public void Setup()
        {
            _clientCredential = new ClientCredential("appSecret");
            _mockAuthResult = MockAuthResult.GetAuthenticationResult(null);
            _mockClientApplicationBase = new MockConfidentialClientApplication(null, _commonAuthority, false, _clientId, _mockAuthResult);
        }

        [TestMethod]
        public void ClientCredentialProvider_ShouldConstructAuthProviderWithConfidentialClientApp()
        {
            ConfidentialClientApplication cca = new ConfidentialClientApplication(_clientId, _redirectUri, _clientCredential, new TokenCache(), null);
            ClientCredentialProvider auth = new ClientCredentialProvider(cca);

            Assert.IsInstanceOfType(auth, typeof(IAuthenticationProvider), "Unexpected auth provider set.");
            Assert.IsNotNull(auth.ClientApplication, "Client application not initialized.");
            Assert.AreSame(cca, auth.ClientApplication, "Wrong client application set.");
        }

        [TestMethod]
        public void ClientCredentialProvider_ConstructorShouldThrowExceptionWithNullConfidentialClientApp()
        {
            GraphAuthException ex = Assert.ThrowsException<GraphAuthException>(() => new ClientCredentialProvider(null));

            Assert.AreEqual(ex.Error.Code, ErrorConstants.Codes.InvalidRequest, "Invalid exception code.");
            Assert.AreEqual(ex.Error.Message, string.Format(ErrorConstants.Message.NullValue, "confidentialClientApplication"), "Invalid exception message.");
        }

        [TestMethod]
        public void ClientCredentialProvider_ShouldCreateConfidentialClientApplicationWithMandatoryParams()
        {
            IClientApplicationBase clientApp = ClientCredentialProvider.CreateClientApplication(_clientId, _clientCredential);

            Assert.IsInstanceOfType(clientApp, typeof(ConfidentialClientApplication), "Unexpected client application set.");
            Assert.AreEqual(_clientId, clientApp.ClientId, "Wrong client id set.");
            Assert.AreEqual(string.Format(AuthConstants.CloudList[NationalCloud.Global], AuthConstants.Tenants.Common), clientApp.Authority, "Wrong authority set.");
        }

        [TestMethod]
        public void ClientCredentialProvider_ShouldCreateConfidentialClientApplicationForConfiguredCloud()
        {
            string tenant = "infotest";
            IClientApplicationBase clientApp = ClientCredentialProvider.CreateClientApplication(_clientId, _clientCredential, null, tenant, NationalCloud.China);

            Assert.IsInstanceOfType(clientApp, typeof(ConfidentialClientApplication), "Unexpected client application set.");
            Assert.AreEqual(_clientId, clientApp.ClientId, "Wrong client id set.");
            Assert.AreEqual(string.Format(AuthConstants.CloudList[NationalCloud.China], tenant), clientApp.Authority, "Wrong authority set.");
        }

        [TestMethod]
        public async Task ClientCredentialProvider_ShouldGetNewAccessTokenWhenUserAccountIsNull()
        {
            HttpRequestMessage httpRequestMessage = new HttpRequestMessage(HttpMethod.Get, "http://example.org/foo");
            _mockClientApplicationBase.Setup((cca) => cca.AcquireTokenForClientAsync(new string[] { "https://graph.microsoft.com/.default" }, false))
                .ReturnsAsync(_mockAuthResult);

            ClientCredentialProvider authProvider = new ClientCredentialProvider(_mockClientApplicationBase.Object);

            await authProvider.AuthenticateRequestAsync(httpRequestMessage);

            Assert.IsInstanceOfType(authProvider.ClientApplication, typeof(IConfidentialClientApplication), "Unexpected client application set.");
            Assert.IsNotNull(httpRequestMessage.Headers.Authorization, "Unexpected auhtorization header set.");
            Assert.AreEqual(_mockAuthResult.AccessToken, httpRequestMessage.Headers.Authorization.Parameter, "Unexpected access token set.");
        }
    }
}
