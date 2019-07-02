namespace Microsoft.Graph.Auth.Test.PublicClient
{
    using Microsoft.Identity.Client;
    using Moq;
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using Xunit;

    public class UsernamePasswordProviderTests
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

            UsernamePasswordProvider auth = new UsernamePasswordProvider(publicClientApplication, scopes);

            Assert.IsAssignableFrom<IAuthenticationProvider>(auth);
            Assert.NotNull(auth.ClientApplication);
            Assert.Same(publicClientApplication, auth.ClientApplication);
        }

        [Fact]
        public void ConstructorShouldThrowExceptionWithNullPublicClientApp()
        {
            IEnumerable<string> scopes = new List<string> { "User.ReadBasic.All" };

            AuthenticationException ex = Assert.Throws<AuthenticationException>(() => new UsernamePasswordProvider(null, scopes));

            Assert.Equal(ex.Error.Code, ErrorConstants.Codes.InvalidRequest);
            Assert.Equal(ex.Error.Message, String.Format(ErrorConstants.Message.NullValue, "publicClientApplication"));
        }

        [Fact]
        public void ShouldUseDefaultScopeUrlWhenScopeIsNull()
        {
            var mock = Mock.Of<IPublicClientApplication>();

            UsernamePasswordProvider authProvider = new UsernamePasswordProvider(mock, null);

            Assert.NotNull(authProvider.Scopes);
            Assert.True(authProvider.Scopes.Count().Equals(1));
            Assert.Equal(AuthConstants.DefaultScopeUrl, authProvider.Scopes.FirstOrDefault());
        }

        [Fact]
        public void ShouldThrowExceptionWhenScopesAreEmpty()
        {
            var mock = Mock.Of<IPublicClientApplication>();

            AuthenticationException ex = Assert.Throws<AuthenticationException>(() => new UsernamePasswordProvider(mock, Enumerable.Empty<string>()));

            Assert.Equal(ex.Error.Message, ErrorConstants.Message.EmptyScopes);
            Assert.Equal(ex.Error.Code, ErrorConstants.Codes.InvalidRequest);
        }
    }
}