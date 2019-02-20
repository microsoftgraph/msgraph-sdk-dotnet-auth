namespace Microsoft.Graph.Auth.Test.Mocks
{
    using Microsoft.Identity.Client;
    using Moq;
    using System.Collections.Generic;
    using System.Linq;
    using System.Threading.Tasks;
    public class MockPublicClientApplication : Mock<IPublicClientApplication>
    {
        public MockPublicClientApplication(string[] scopes, IEnumerable<IAccount> accounts, string authority, bool forceRefresh, string clientId, AuthenticationResult authenticationResult)
            : base(MockBehavior.Strict)
        {
            this.SetupAllProperties();

            this.SetupGet(
                publicClientApplication => publicClientApplication.ClientId)
                .Returns(clientId);

            this.SetupGet(
                publicClientApplication => publicClientApplication.Authority)
                .Returns(authority);

            this.Setup(
                publicClientApplication => publicClientApplication.GetAccountsAsync())
                .Returns(Task.FromResult(accounts));

            this.Setup(
                publicClientApplication => publicClientApplication.AcquireTokenSilentAsync(scopes, accounts.FirstOrDefault(), authority, forceRefresh))
                .Returns(Task.FromResult(authenticationResult));
        }
    }

    public class MockConfidentialClientApplication : Mock<IConfidentialClientApplication>
    {
        public MockConfidentialClientApplication(string[] scopes, IEnumerable<IAccount> accounts, string authority, bool forceRefresh, string clientId, AuthenticationResult authenticationResult)
            : base(MockBehavior.Strict)
        {
            this.SetupAllProperties();

            this.SetupGet(
                publicClientApplication => publicClientApplication.ClientId)
                .Returns(clientId);

            this.SetupGet(
                publicClientApplication => publicClientApplication.Authority)
                .Returns(authority);

            this.Setup(
                publicClientApplication => publicClientApplication.GetAccountsAsync())
                .Returns(Task.FromResult(accounts));

            this.Setup(
                publicClientApplication => publicClientApplication.AcquireTokenSilentAsync(scopes, accounts.FirstOrDefault(), authority, forceRefresh))
                .Returns(Task.FromResult(authenticationResult));

            //AcquireTokenSilentAsync(Scopes, users.FirstOrDefault(), ClientApplication.Authority, forceRefresh);
        }
    }
}
