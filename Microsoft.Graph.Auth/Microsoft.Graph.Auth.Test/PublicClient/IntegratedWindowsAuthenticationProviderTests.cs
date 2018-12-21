﻿using Microsoft.Graph.Auth.Test.Mocks;
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
    public class IntegratedWindowsAuthenticationProviderTests
    {
        private MockTokenCacheProvider tokenCacheProvider;
        private IntegratedWindowsAuthenticationProvider intergratedWindowsAuthFlowProvider;
        private IPublicClientApplication publicClientAppMock;
        private string clientId = "client-id";
        private string organizationsAuthority = "https://login.microsoftonline.com/organizations/";
        private string[] scopes = new string[] { "User.Read" };
        private MockUserAccount mockUserAccount, mockUserAccount2;

        [TestInitialize]
        public void Setup()
        {
            mockUserAccount = new MockUserAccount("xyz@test.net", "login.microsoftonline.com");
            mockUserAccount2 = new MockUserAccount("abc@test.com", "login.microsoftonline.com");
            tokenCacheProvider = new MockTokenCacheProvider();
            intergratedWindowsAuthFlowProvider = new IntegratedWindowsAuthenticationProvider(clientId, tokenCacheProvider, scopes);
        }

        [TestMethod]
        public void IntegratedWindowsAuthenticationProvider_ConstructorWithNullableParams()
        {
            Assert.IsInstanceOfType(intergratedWindowsAuthFlowProvider, typeof(IAuthenticationProvider));
            Assert.IsNotNull(intergratedWindowsAuthFlowProvider.ClientApplication);
            Assert.IsInstanceOfType(intergratedWindowsAuthFlowProvider.ClientApplication, typeof(IPublicClientApplication));
            Assert.AreEqual(intergratedWindowsAuthFlowProvider.ClientApplication.ClientId, clientId);
            Assert.AreEqual(intergratedWindowsAuthFlowProvider.ClientApplication.Authority, "https://login.microsoftonline.com/organizations/");
        }

        [TestMethod]
        public void IntegratedWindowsAuthenticationProvider_ConstructorWithoutNullableParams()
        {
            var authProvider = new IntegratedWindowsAuthenticationProvider(clientId, tokenCacheProvider, scopes, mockUserAccount.Username, NationalCloud.China, "contoso");

            Assert.IsInstanceOfType(authProvider, typeof(IAuthenticationProvider));
            Assert.IsNotNull(authProvider.ClientApplication);
            Assert.IsInstanceOfType(authProvider.ClientApplication, typeof(IPublicClientApplication));
            Assert.AreEqual(authProvider.ClientApplication.ClientId, clientId);
            Assert.AreEqual(authProvider.ClientApplication.Authority, "https://login.chinacloudapi.cn/contoso/");
        }

        [TestMethod]
        public void IntegratedWindowsAuthenticationProvider_ConstructorWithPublicClientApplication()
        {
            var publicClient = new PublicClientApplication(clientId);
            var authProvider = new IntegratedWindowsAuthenticationProvider(publicClient, scopes);

            Assert.IsInstanceOfType(authProvider, typeof(IAuthenticationProvider));
            Assert.IsNotNull(authProvider.ClientApplication);
            Assert.IsInstanceOfType(authProvider.ClientApplication, typeof(IPublicClientApplication));
            Assert.AreEqual(intergratedWindowsAuthFlowProvider.ClientApplication.ClientId, clientId);
            Assert.AreEqual(intergratedWindowsAuthFlowProvider.ClientApplication.Authority, "https://login.microsoftonline.com/organizations/");
        }

        [TestMethod]
        public async Task IntegratedWindowsAuthenticationProvider_WithNoUserAccountInCache()
        {
            var httpRequestMessage = new HttpRequestMessage(HttpMethod.Get, "http://example.org/foo");
            var expectedAuthResult = MockAuthResult.GetAuthenticationResult(scopes);
            var mockAuthResult = MockAuthResult.GetAuthenticationResult(scopes);
            var mockAuthResult2 = MockAuthResult.GetAuthenticationResult(scopes);

            publicClientAppMock = Substitute.For<IPublicClientApplication>();
            publicClientAppMock.GetAccountsAsync().ReturnsForAnyArgs(new List<IAccount>());
            publicClientAppMock.AcquireTokenSilentAsync(scopes, mockUserAccount).ReturnsForAnyArgs(mockAuthResult);
            publicClientAppMock.AcquireTokenByIntegratedWindowsAuthAsync(scopes, mockUserAccount.Username).ReturnsForAnyArgs(mockAuthResult2);
            publicClientAppMock.AcquireTokenByIntegratedWindowsAuthAsync(scopes).ReturnsForAnyArgs(expectedAuthResult);

            intergratedWindowsAuthFlowProvider.ClientApplication = publicClientAppMock;
            await intergratedWindowsAuthFlowProvider.AuthenticateRequestAsync(httpRequestMessage);

            Assert.IsInstanceOfType(intergratedWindowsAuthFlowProvider, typeof(IAuthenticationProvider));
            Assert.IsInstanceOfType(intergratedWindowsAuthFlowProvider.ClientApplication, typeof(IPublicClientApplication));
            Assert.IsNotNull(httpRequestMessage.Headers.Authorization);
            Assert.AreEqual(httpRequestMessage.Headers.Authorization.Scheme, CoreConstants.Headers.Bearer);
            Assert.AreEqual(httpRequestMessage.Headers.Authorization.Parameter, expectedAuthResult.AccessToken);
        }

        [TestMethod]
        public async Task IntegratedWindowsAuthenticationProvider_WithUserAccountInCache()
        {
            var httpRequestMessage = new HttpRequestMessage(HttpMethod.Post, "http://example.org/foo");
            var expectedAuthResult = MockAuthResult.GetAuthenticationResult(scopes);
            var mockAuthResult = MockAuthResult.GetAuthenticationResult(scopes);
            var mockAuthResult2 = MockAuthResult.GetAuthenticationResult(scopes);

            publicClientAppMock = Substitute.For<IPublicClientApplication>();
            publicClientAppMock.GetAccountsAsync().ReturnsForAnyArgs(new List<IAccount> { mockUserAccount });
            publicClientAppMock.AcquireTokenSilentAsync(scopes, mockUserAccount).ReturnsForAnyArgs(expectedAuthResult);
            publicClientAppMock.AcquireTokenByIntegratedWindowsAuthAsync(scopes, mockUserAccount.Username).ReturnsForAnyArgs(mockAuthResult);
            publicClientAppMock.AcquireTokenByIntegratedWindowsAuthAsync(scopes).ReturnsForAnyArgs(mockAuthResult2);

            intergratedWindowsAuthFlowProvider.ClientApplication = publicClientAppMock;
            await intergratedWindowsAuthFlowProvider.AuthenticateRequestAsync(httpRequestMessage);

            Assert.IsInstanceOfType(intergratedWindowsAuthFlowProvider, typeof(IAuthenticationProvider));
            Assert.IsInstanceOfType(intergratedWindowsAuthFlowProvider.ClientApplication, typeof(IPublicClientApplication));
            Assert.IsNotNull(httpRequestMessage.Headers.Authorization);
            Assert.AreEqual(httpRequestMessage.Headers.Authorization.Scheme, CoreConstants.Headers.Bearer);
            Assert.AreEqual(httpRequestMessage.Headers.Authorization.Parameter, expectedAuthResult.AccessToken);
        }
    }
}