using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Graph.Auth;
using Microsoft.Identity.Client;

namespace Microsoft.Graph.Auth.Test.Extensions
{
    [TestClass]
    public class BaseRequestExtensionsTests
    {
        private const string baseUrl = "http://foo.bar";
        private BaseClient baseClient;

        [TestInitialize]
        public void Setup()
        {
            baseClient = new BaseClient(baseUrl, null);
        }

        [TestMethod]
        public void WithScopes_ShouldAddScopesToAuthProviderOptions()
        {
            BaseRequest baseRequest = new BaseRequest(baseUrl, baseClient);
            string[] scopes = new string[] { "Foo.Bar", "Bar.Foo.Bar" };

            baseRequest.WithScopes(scopes);

            var httpRequestMessage = baseRequest.GetHttpRequestMessage();
            MsalAuthProviderOption msalAuthProviderOption = httpRequestMessage.GetMsalAuthProviderOption();

            Assert.IsNotNull(msalAuthProviderOption);
            Assert.AreSame(scopes, msalAuthProviderOption.Scopes);
        }

        [TestMethod]
        public void WithForceRefresh_ShouldAddForceRefreshToAuthProviderOptions()
        {
            BaseRequest baseRequest = new BaseRequest(baseUrl, baseClient);

            baseRequest.WithForceRefresh(true);

            var httpRequestMessage = baseRequest.GetHttpRequestMessage();
            MsalAuthProviderOption msalAuthProviderOption = httpRequestMessage.GetMsalAuthProviderOption();

            Assert.IsNotNull(msalAuthProviderOption);
            Assert.IsTrue(msalAuthProviderOption.ForceRefresh);
        }

        [TestMethod]
        public void WithUserAccount_ShouldAddUserAccountToAuthProviderOption()
        {
            BaseRequest baseRequest = new BaseRequest(baseUrl, baseClient);
            GraphUserAccount graphUser = new GraphUserAccount
            {
                Email = "foo@bar.com",
                ObjectId = Guid.NewGuid().ToString(),
                TenantId = Guid.NewGuid().ToString()
            };

            baseRequest.WithUserAccount(graphUser);

            var httpRequestMessage = baseRequest.GetHttpRequestMessage();
            MsalAuthProviderOption msalAuthProviderOption = httpRequestMessage.GetMsalAuthProviderOption();

            Assert.IsNotNull(msalAuthProviderOption);
            Assert.AreSame(graphUser, msalAuthProviderOption.UserAccount);
            Assert.AreEqual(graphUser.Email, msalAuthProviderOption.UserAccount.Email);
            Assert.AreEqual(graphUser.ObjectId, msalAuthProviderOption.UserAccount.ObjectId);
        }

        [TestMethod]
        public void WithUserAssertion_ShouldAddUserAssertionToAuthProviderOption()
        {
            var baseRequest = new BaseRequest(baseUrl, baseClient);
            UserAssertion userAssertion = new UserAssertion("access_token");

            baseRequest.WithUserAssertion(userAssertion);

            var httpRequestMessage = baseRequest.GetHttpRequestMessage();
            MsalAuthProviderOption msalAuthProviderOption = httpRequestMessage.GetMsalAuthProviderOption();

            Assert.IsNotNull(msalAuthProviderOption);
            Assert.AreSame(userAssertion, msalAuthProviderOption.UserAssertion);
            Assert.AreEqual(userAssertion.Assertion, msalAuthProviderOption.UserAssertion.Assertion);
        }

        [TestMethod]
        public void WithUsernamePassword_ShouldAddUsernameAndPasswordToAuthProviderOption()
        {
            var baseRequest = new BaseRequest(baseUrl, baseClient);
            string email = "foo@bar.com";
            string password = "veryComnplex";

            baseRequest.WithUsernamePassword(email, password);

            var httpRequestMessage = baseRequest.GetHttpRequestMessage();
            MsalAuthProviderOption msalAuthProviderOption = httpRequestMessage.GetMsalAuthProviderOption();

            Assert.IsNotNull(msalAuthProviderOption);
            Assert.AreEqual(email, msalAuthProviderOption.UserAccount.Email);
            Assert.AreEqual(password, msalAuthProviderOption.Password);
        }

    }
}
