namespace Microsoft.Graph.Auth.Test.ConfidentialClient
{
    using Microsoft.Identity.Client;
    using Moq;
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Net.Http;
    using System.Threading.Tasks;
    using Xunit;
    public class AuthorizationCodeProviderTests
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

            AuthorizationCodeProvider auth = new AuthorizationCodeProvider(confidentialClientApplication, scopes);

            Assert.IsAssignableFrom<IAuthenticationProvider>(auth);
            Assert.NotNull(auth.ClientApplication);
            Assert.Same(confidentialClientApplication, auth.ClientApplication);
        }

        [Fact]
        public void ConstructorShouldThrowExceptionWithNullConfidentialClientApp()
        {
            IEnumerable<string> scopes = new List<string> { "User.ReadBasic.All" };

            AuthenticationException ex = Assert.Throws<AuthenticationException>(() => new AuthorizationCodeProvider(null, scopes));

            Assert.Equal(ex.Error.Code, ErrorConstants.Codes.InvalidRequest);
            Assert.Equal(ex.Error.Message, String.Format(ErrorConstants.Message.NullValue, "confidentialClientApplication"));
        }

        [Fact]
        public void ShouldUseDefaultScopeUrlWhenScopeIsNull()
        {
            var mock = Mock.Of<IConfidentialClientApplication>();

            AuthorizationCodeProvider authCodeFlowProvider = new AuthorizationCodeProvider(mock, null);

            Assert.NotNull(authCodeFlowProvider.Scopes);
            Assert.True(authCodeFlowProvider.Scopes.Count().Equals(1));
            Assert.Equal(AuthConstants.DefaultScopeUrl, authCodeFlowProvider.Scopes.FirstOrDefault());
        }

        [Fact]
        public void ShouldThrowExceptionWhenScopesAreEmpty()
        {
            var mock = Mock.Of<IConfidentialClientApplication>();

            AuthenticationException ex = Assert.Throws<AuthenticationException>(() => new AuthorizationCodeProvider(mock, Enumerable.Empty<string>()));

            Assert.Equal(ex.Error.Message, ErrorConstants.Message.EmptyScopes);
            Assert.Equal(ex.Error.Code, ErrorConstants.Codes.InvalidRequest);
        }

        [Fact]
        public async Task ShouldThrowChallangeRequiredExceptionWhenNoUserAccountIsNull()
        {
            IEnumerable<string> scopes = new List<string> { "User.ReadBasic.All" };

            HttpRequestMessage httpRequestMessage = new HttpRequestMessage(HttpMethod.Get, "http://example.org/foo");

            var mock = Mock.Of<IConfidentialClientApplication>();

            AuthorizationCodeProvider authCodeFlowProvider = new AuthorizationCodeProvider(mock, scopes);

            AuthenticationException ex = await Assert.ThrowsAsync<AuthenticationException>(async () => await authCodeFlowProvider.AuthenticateRequestAsync(httpRequestMessage));

            Assert.Equal(ErrorConstants.Message.AuthenticationChallengeRequired, ex.Error.Message);
            Assert.IsAssignableFrom<IConfidentialClientApplication>(authCodeFlowProvider.ClientApplication);
            Assert.Null(httpRequestMessage.Headers.Authorization);
        }
    }
}