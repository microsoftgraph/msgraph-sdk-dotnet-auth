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

    public class ClientCredentialProviderTests
    {
        [Fact]
        public void ShouldConstructAuthProviderWithConfidentialClientApp()
        {
            string clientId = "00000000-0000-0000-0000-000000000000";
            string clientSecret = "00000000-0000-0000-0000-000000000000";
            string authority = "https://login.microsoftonline.com/organizations/";
            string redirectUri = "https://login.microsoftonline.com/common/oauth2/deviceauth";
            
            IConfidentialClientApplication confidentialClientApplication = ConfidentialClientApplicationBuilder
                .Create(clientId)
                .WithRedirectUri(redirectUri)
                .WithClientSecret(clientSecret)
                .WithAuthority(authority)
                .Build();

            ClientCredentialProvider auth = new ClientCredentialProvider(confidentialClientApplication);

            Assert.IsAssignableFrom<IAuthenticationProvider>(auth);
            Assert.NotNull(auth.ClientApplication);
            Assert.Same(confidentialClientApplication, auth.ClientApplication);
        }

        [Fact]
        public void ConstructorShouldThrowExceptionWithNullConfidentialClientApp()
        {
            AuthenticationException ex = Assert.Throws<AuthenticationException>(() => new ClientCredentialProvider(null));

            Assert.Equal(ex.Error.Code, ErrorConstants.Codes.InvalidRequest);
            Assert.Equal(ex.Error.Message, String.Format(ErrorConstants.Message.NullValue, "confidentialClientApplication"));
        }

        [Fact]
        public void ShouldCreateConfidentialClientApplicationWithMandatorySecretParams()
        {
            string clientId = "00000000-0000-0000-0000-000000000000";
            string clientSecret = "00000000-0000-0000-0000-000000000000";

            IClientApplicationBase clientApp = ClientCredentialProvider.CreateClientApplication(clientId, clientSecret);

            Assert.IsAssignableFrom<ConfidentialClientApplication>(clientApp);
            Assert.Equal(clientId, clientApp.AppConfig.ClientId);
            Assert.Equal(AzureCloudInstance.AzurePublic.GetAuthorityUrl(AadAuthorityAudience.AzureAdMultipleOrgs), clientApp.Authority);
        }

        [Fact]
        public void ShouldCreateConfidentialClientApplicationWithMandatoryCertificateParams()
        {
            string clientId = "00000000-0000-0000-0000-000000000000";

            var clientCertificate = Mock.Of<X509Certificate2>();

            IClientApplicationBase clientApp = ClientCredentialProvider.CreateClientApplication(clientId, clientCertificate);

            Assert.IsAssignableFrom<ConfidentialClientApplication>(clientApp);
            Assert.Equal(clientId, clientApp.AppConfig.ClientId);
            Assert.Equal(AzureCloudInstance.AzurePublic.GetAuthorityUrl(AadAuthorityAudience.AzureAdMultipleOrgs), clientApp.Authority);
        }

        [Fact]
        public void ShouldCreateConfidentialClientApplicationForConfiguredCloud()
        {
            string clientId = "00000000-0000-0000-0000-000000000000";
            string testTenant = "infotest";
            string clientSecret = "00000000-0000-0000-0000-000000000000";

            IClientApplicationBase clientApp = ClientCredentialProvider.CreateClientApplication(clientId, clientSecret, tenant: testTenant, cloud: AzureCloudInstance.AzureChina);

            Assert.IsAssignableFrom<ConfidentialClientApplication>(clientApp);
            Assert.Equal(clientId, clientApp.AppConfig.ClientId);
            Assert.Equal(AzureCloudInstance.AzureChina.GetAuthorityUrl(AadAuthorityAudience.AzureAdMyOrg, testTenant), clientApp.Authority);
        }
    }
}
