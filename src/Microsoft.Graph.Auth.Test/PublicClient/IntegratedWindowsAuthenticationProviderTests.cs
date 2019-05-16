namespace Microsoft.Graph.Auth.Test.PublicClient
{
    using Microsoft.Graph.Auth.Test.Extensions;
    using Microsoft.Identity.Client;
    using Moq;
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Net.Http;
    using Xunit;

    public class IntegratedWindowsAuthenticationProviderTests
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

            IntegratedWindowsAuthenticationProvider auth = new IntegratedWindowsAuthenticationProvider(publicClientApplication, scopes);

            Assert.IsAssignableFrom<IAuthenticationProvider>(auth);
            Assert.NotNull(auth.ClientApplication);
            Assert.Same(publicClientApplication, auth.ClientApplication);
        }

        [Fact]
        public void ConstructorShouldThrowExceptionWithNullPublicClientApp()
        {
            IEnumerable<string> scopes = new List<string> { "User.ReadBasic.All" };

            AuthenticationException ex = Assert.Throws<AuthenticationException>(() => new IntegratedWindowsAuthenticationProvider(null, scopes));

            Assert.Equal(ex.Error.Code, ErrorConstants.Codes.InvalidRequest);
            Assert.Equal(ex.Error.Message, string.Format(ErrorConstants.Message.NullValue, "publicClientApplication"));
        }

        [Fact]
        public void ShouldCreatePublicClientApplicationWithMandatoryParams()
        {
            string clientId = "00000000-0000-0000-0000-000000000000";

            IClientApplicationBase clientApp = IntegratedWindowsAuthenticationProvider.CreateClientApplication(clientId);

            Assert.IsAssignableFrom<PublicClientApplication>(clientApp);
            Assert.Equal(clientId, clientApp.AppConfig.ClientId);
            Assert.Equal(AzureCloudInstance.AzurePublic.GetAuthorityUrl(AadAuthorityAudience.AzureAdMultipleOrgs), clientApp.Authority);
        }

        [Fact]
        public void ShouldCreatePublicClientApplicationForConfiguredCloud()
        {
            string clientId = "00000000-0000-0000-0000-000000000000";
            string testTenant = "infotest";
            IClientApplicationBase clientApp = IntegratedWindowsAuthenticationProvider.CreateClientApplication(clientId, tenant: testTenant, cloud: AzureCloudInstance.AzureChina);

            Assert.IsAssignableFrom<PublicClientApplication>(clientApp);
            Assert.Equal(clientId, clientApp.AppConfig.ClientId);
            Assert.Equal(AzureCloudInstance.AzureChina.GetAuthorityUrl(AadAuthorityAudience.AzureAdMyOrg, testTenant), clientApp.Authority);
        }

        [Fact]
        public void ShouldUseDefaultScopeUrlWhenScopeIsNull()
        {
            var mock = Mock.Of<IPublicClientApplication>();

            IntegratedWindowsAuthenticationProvider authProvider = new IntegratedWindowsAuthenticationProvider(mock, null);

            Assert.NotNull(authProvider.Scopes);
            Assert.True(authProvider.Scopes.Count().Equals(1));
            Assert.Equal(AuthConstants.DefaultScopeUrl, authProvider.Scopes.FirstOrDefault());
        }

        [Fact]
        public void ShouldThrowExceptionWhenScopesAreEmpty()
        {
            var mock = Mock.Of<IPublicClientApplication>();

            AuthenticationException ex = Assert.Throws<AuthenticationException>(() => new IntegratedWindowsAuthenticationProvider(mock, Enumerable.Empty<string>()));

            Assert.Equal(ex.Error.Message, ErrorConstants.Message.EmptyScopes);
            Assert.Equal(ex.Error.Code, ErrorConstants.Codes.InvalidRequest);
        }
    }
}