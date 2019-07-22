namespace Microsoft.Graph.Auth.Test.ConfidentialClient
{
    using Microsoft.Identity.Client;
    using System;
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
        public void ConstructorShouldUseDefualtScopeWhenScopeisNull()
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

            ClientCredentialProvider auth = new ClientCredentialProvider(confidentialClientApplication, null);

            Assert.NotNull(auth.Scope);
            Assert.Equal(AuthConstants.DefaultScopeUrl, auth.Scope);
        }

        [Fact]
        public void ConstructorShouldThrowExceptionWithNullConfidentialClientApp()
        {
            AuthenticationException ex = Assert.Throws<AuthenticationException>(() => new ClientCredentialProvider(null));

            Assert.Equal(ex.Error.Code, ErrorConstants.Codes.InvalidRequest);
            Assert.Equal(ex.Error.Message, String.Format(ErrorConstants.Message.NullValue, "confidentialClientApplication"));
        }
    }
}
