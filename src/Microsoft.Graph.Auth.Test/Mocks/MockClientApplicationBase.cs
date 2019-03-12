namespace Microsoft.Graph.Auth.Test.Mocks
{
    using Microsoft.Identity.Client;
    using Moq;
    using System.Collections.Generic;
    using System.Linq;
    using System.Threading.Tasks;
    public class MockPublicClientApplication : Mock<IPublicClientApplication>
    {
        public MockPublicClientApplication(string[] scopes, string authority, bool forceRefresh, string clientId, AuthenticationResult authenticationResult)
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
                .Returns(Task.FromResult(new List<IAccount>().AsEnumerable()));

            this.Setup(
                publicClientApplication => publicClientApplication.AcquireTokenSilentAsync(scopes, It.IsAny<IAccount>(), authority, forceRefresh))
                .Returns(Task.FromResult(authenticationResult));
        }
    }

    public class MockConfidentialClientApplication : Mock<IConfidentialClientApplication>
    {
        public MockConfidentialClientApplication(string[] scopes, string authority, bool forceRefresh, string clientId, AuthenticationResult authenticationResult)
            : base(MockBehavior.Strict)
        {
            this.CallBase = true;

            this.SetupAllProperties();

            this.SetupGet(
                confidentialClientApplication => confidentialClientApplication.ClientId)
                .Returns(clientId);

            this.SetupGet(
                confidentialClientApplication => confidentialClientApplication.Authority)
                .Returns(authority);

            this.Setup(
                confidentialClientApplication => confidentialClientApplication.GetAccountsAsync())
                .Returns(Task.FromResult(new List<IAccount>().AsEnumerable()));

            this.Setup(
                confidentialClientApplication => confidentialClientApplication.AcquireTokenSilentAsync(scopes, It.IsAny<IAccount>(), authority, forceRefresh))
                .ReturnsAsync(authenticationResult);
        }
    }
}
