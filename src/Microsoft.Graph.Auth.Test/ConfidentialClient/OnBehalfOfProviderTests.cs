namespace Microsoft.Graph.Auth.Test.ConfidentialClient
{
    using Microsoft.Graph.Auth.Test.Extensions;
    using Microsoft.Identity.Client;
    using Moq;
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Security.Cryptography.X509Certificates;
    using Xunit;

    public class OnBehalfOfProviderTests
    {
        [Fact]
        public void ShouldConstructAuthProviderWithConfidentialClientApp()
        {
            string clientId = "00000000-0000-0000-0000-000000000000";
            string clientSecret = "00000000-0000-0000-0000-000000000000";
            string authority = "https://login.microsoftonline.com/organizations/";
            string redirectUri = "https://login.microsoftonline.com/common/oauth2/deviceauth";
            IEnumerable<string> scopes = new List<string> { "User.ReadBasic.All" };

            IConfidentialClientApplication confidentialClientApplication = ConfidentialClientApplicationBuilder
                .Create(clientId)
                .WithRedirectUri(redirectUri)
                .WithClientSecret(clientSecret)
                .WithAuthority(authority)
                .Build();

            OnBehalfOfProvider auth = new OnBehalfOfProvider(confidentialClientApplication, scopes);

            Assert.IsAssignableFrom<IAuthenticationProvider>(auth);
            Assert.NotNull(auth.ClientApplication);
            Assert.Same(confidentialClientApplication, auth.ClientApplication);
        }

        [Fact]
        public void ConstructorShouldThrowExceptionWithNullConfidentialClientApp()
        {
            IEnumerable<string> scopes = new List<string> { "User.ReadBasic.All" };

            AuthenticationException ex = Assert.Throws<AuthenticationException>(() => new OnBehalfOfProvider(null, scopes));

            Assert.Equal(ex.Error.Code, ErrorConstants.Codes.InvalidRequest);
            Assert.Equal(ex.Error.Message, String.Format(ErrorConstants.Message.NullValue, "confidentialClientApplication"));
        }

        [Fact]
        public void ShouldCreateConfidentialClientApplicationWithMandatorySecretParams()
        {
            string clientId = "00000000-0000-0000-0000-000000000000";
            string redirectUri = "https://login.microsoftonline.com/common/oauth2/deviceauth";
            string clientSecret = "00000000-0000-0000-0000-000000000000";

            IClientApplicationBase clientApp = OnBehalfOfProvider.CreateClientApplication(clientId, redirectUri, clientSecret);

            Assert.IsAssignableFrom<ConfidentialClientApplication>(clientApp);
            Assert.Equal(clientId, clientApp.AppConfig.ClientId);
            Assert.Equal(AzureCloudInstance.AzurePublic.GetAuthorityUrl(AadAuthorityAudience.AzureAdMultipleOrgs), clientApp.Authority);
        }

        [Fact]
        public void ShouldCreateConfidentialClientApplicationWithMandatoryCertificateParams()
        {
            string clientId = "00000000-0000-0000-0000-000000000000";
            string redirectUri = "https://login.microsoftonline.com/common/oauth2/deviceauth";
            
            var clientCertificate = Mock.Of<X509Certificate2>();
            
            IClientApplicationBase clientApp = OnBehalfOfProvider.CreateClientApplication(clientId, redirectUri, clientCertificate);

            Assert.IsAssignableFrom<ConfidentialClientApplication>(clientApp);
            Assert.Equal(clientId, clientApp.AppConfig.ClientId);
            Assert.Equal(AzureCloudInstance.AzurePublic.GetAuthorityUrl(AadAuthorityAudience.AzureAdMultipleOrgs), clientApp.Authority);
        }

        [Fact]
        public void ShouldCreateConfidentialClientApplicationForConfiguredCloud()
        {
            string clientId = "00000000-0000-0000-0000-000000000000";
            string testTenant = "infotest";
            string redirectUri = "https://login.microsoftonline.com/common/oauth2/deviceauth";
            string clientSecret = "00000000-0000-0000-0000-000000000000";

            IClientApplicationBase clientApp = OnBehalfOfProvider.CreateClientApplication(clientId, redirectUri, clientSecret, tenant: testTenant, cloud: AzureCloudInstance.AzureChina);

            Assert.IsAssignableFrom<ConfidentialClientApplication>(clientApp);
            Assert.Equal(clientId, clientApp.AppConfig.ClientId);
            Assert.Equal(AzureCloudInstance.AzureChina.GetAuthorityUrl(AadAuthorityAudience.AzureAdMyOrg, testTenant), clientApp.Authority);
        }

        [Fact]
        public void ShouldUseDefaultScopeUrlWhenScopeIsNull()
        {
            var mock = Mock.Of<IConfidentialClientApplication>();

            OnBehalfOfProvider onBehalfOfProvider = new OnBehalfOfProvider(mock, null);

            Assert.NotNull(onBehalfOfProvider.Scopes);
            Assert.True(onBehalfOfProvider.Scopes.Count().Equals(1));
            Assert.Equal(AuthConstants.DefaultScopeUrl, onBehalfOfProvider.Scopes.FirstOrDefault());
        }

        [Fact]
        public void ShouldThrowExceptionWhenScopesAreEmpty()
        {
            var mock = Mock.Of<IConfidentialClientApplication>();

            AuthenticationException ex = Assert.Throws<AuthenticationException>(() => new OnBehalfOfProvider(mock, Enumerable.Empty<string>()));

            Assert.Equal(ex.Error.Message, ErrorConstants.Message.EmptyScopes);
            Assert.Equal(ex.Error.Code, ErrorConstants.Codes.InvalidRequest);
        }

        [Fact]
        public void ShouldGetGraphUserAccountFromJwtString()
        {
            IEnumerable<string> scopes = new List<string> { "User.ReadBasic.All" };
            string jwtAccessToken = "eyJ0eXAiOiJKV1QiLCJub25jZSI6IkFBMjMyVEVTVCIsImFsZyI6IkhTMjU2In0.eyJmYW1pbHlfbmFtZSI6IkRvZSIsImdpdmVuX25hbWUiOiJKb2huIiwibmFtZSI6IkpvaG4gRG9lIiwib2lkIjoiZTYwMmFkYTctNmVmZC00ZTE4LWE5NzktNjNjMDJiOWYzYzc2Iiwic2NwIjoiVXNlci5SZWFkQmFzaWMuQWxsIiwidGlkIjoiNmJjMTUzMzUtZTJiOC00YTlhLTg2ODMtYTUyYTI2YzhjNTgzIiwidW5pcXVlX25hbWUiOiJqb2huQGRvZS50ZXN0LmNvbSIsInVwbiI6ImpvaG5AZG9lLnRlc3QuY29tIn0.hf9xI5XYBjGec-4n4_Kxj8Nd2YHBtihdevYhzFxbpXQ";

            var mock = Mock.Of<IConfidentialClientApplication>();

            OnBehalfOfProvider authProvider = new OnBehalfOfProvider(mock, scopes);
            GraphUserAccount userAccount = authProvider.GetGraphUserAccountFromJwt(jwtAccessToken);

            Assert.NotNull(userAccount);
            Assert.Equal("e602ada7-6efd-4e18-a979-63c02b9f3c76", userAccount?.ObjectId);
            Assert.Equal("6bc15335-e2b8-4a9a-8683-a52a26c8c583", userAccount?.TenantId);
            Assert.Equal("john@doe.test.com", userAccount?.Email);
        }
    }
}