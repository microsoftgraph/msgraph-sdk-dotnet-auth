namespace Microsoft.Graph.Auth.Test.PublicClient
{
    using Microsoft.Graph.Auth.Test.Extensions;
    using Microsoft.Identity.Client;
    using Moq;
    using System.Collections.Generic;
    using System.Linq;
    using Xunit;

    public class DeviceCodeProviderTests
    {
        [Fact]
        public void ShouldConstructAuthProviderWithPublicClientApp()
        {
            string clientId = "00000000-0000-0000-0000-000000000000";
            string authority = "https://login.microsoftonline.com/organizations/";
            IEnumerable<string> scopes = new List<string> { "User.ReadBasic.All" };

            IPublicClientApplication publicClientApplication = PublicClientApplicationBuilder
                .Create(clientId)
                .WithAuthority(authority)
                .Build();

            DeviceCodeProvider auth = new DeviceCodeProvider(publicClientApplication, scopes);

            Assert.IsAssignableFrom<IAuthenticationProvider>(auth);
            Assert.NotNull(auth.ClientApplication);
            Assert.Same(publicClientApplication, auth.ClientApplication);
        }

        [Fact]
        public void ConstructorShouldThrowExceptionWithNullPublicClientApp()
        {
            IEnumerable<string> scopes = new List<string> { "User.ReadBasic.All" };

            AuthenticationException ex = Assert.Throws<AuthenticationException>(() => new DeviceCodeProvider(null, scopes));

            Assert.Equal(ex.Error.Code, ErrorConstants.Codes.InvalidRequest);
            Assert.Equal(ex.Error.Message, string.Format(ErrorConstants.Message.NullValue, "publicClientApplication"));
        }

        [Fact]
        public void ShouldCreatePublicClientApplicationWithMandatoryParams()
        {
            string clientId = "00000000-0000-0000-0000-000000000000";

            IClientApplicationBase clientApp = DeviceCodeProvider.CreateClientApplication(clientId);

            Assert.IsAssignableFrom<PublicClientApplication>(clientApp);
            Assert.Equal(clientId, clientApp.AppConfig.ClientId);
            Assert.Equal(AzureCloudInstance.AzurePublic.GetAuthorityUrl(AadAuthorityAudience.AzureAdMultipleOrgs), clientApp.Authority);
        }

        [Fact]
        public void ShouldCreatePublicClientApplicationForConfiguredCloud()
        {
            string clientId = "00000000-0000-0000-0000-000000000000";
            string testTenant = "infotest";

            IClientApplicationBase clientApp = DeviceCodeProvider.CreateClientApplication(clientId, tenant: testTenant, cloud: AzureCloudInstance.AzureChina);

            Assert.IsAssignableFrom<PublicClientApplication>(clientApp);
            Assert.Equal(clientId, clientApp.AppConfig.ClientId);
            Assert.Equal(AzureCloudInstance.AzureChina.GetAuthorityUrl(AadAuthorityAudience.AzureAdMyOrg, testTenant), clientApp.Authority);
        }

        [Fact]
        public void ShouldUseDefaultScopeUrlWhenScopeIsNull()
        {
            var mock = Mock.Of<IPublicClientApplication>();

            DeviceCodeProvider deviceCodeProvider = new DeviceCodeProvider(mock, null);

            Assert.NotNull(deviceCodeProvider.Scopes);
            Assert.True(deviceCodeProvider.Scopes.Count().Equals(1));
            Assert.Equal(AuthConstants.DefaultScopeUrl, deviceCodeProvider.Scopes.FirstOrDefault());
        }

        [Fact]
        public void ShouldThrowExceptionWhenScopesAreEmpty()
        {
            var mock = Mock.Of<IPublicClientApplication>();

            AuthenticationException ex = Assert.Throws<AuthenticationException>(() => new DeviceCodeProvider(mock, Enumerable.Empty<string>()));

            Assert.Equal(ex.Error.Message, ErrorConstants.Message.EmptyScopes);
            Assert.Equal(ex.Error.Code, ErrorConstants.Codes.InvalidRequest);
        }
    }
}