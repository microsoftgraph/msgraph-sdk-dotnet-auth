namespace Microsoft.Graph.Auth.Test.Extensions
{
    using System.Net.Http;
    using Xunit;

    public class HttpRequestMessageExtensionsTests
    {
        [Fact]
        public void CanExtractClaimsFromICaeAuthenticationProviderOption()
        {
            // Arrange
            var httpRequestMessage = new HttpRequestMessage(HttpMethod.Get, "http://example.com/bar");
            var authenticationHandlerOption = new AuthenticationHandlerOption();
            var authenticationProviderOption = new CaeAuthProviderOptionTest()
            {
                Scopes = new [] { "User.Read" },
                Claims = "claim"
            };
            authenticationHandlerOption.AuthenticationProviderOption = authenticationProviderOption;

            // set the original AuthenticationProviderOptionTest as the auth provider
            var originalRequestContext = httpRequestMessage.GetRequestContext();
            originalRequestContext.MiddlewareOptions[typeof(AuthenticationHandlerOption).ToString()] = authenticationHandlerOption;
            httpRequestMessage.Properties[typeof(GraphRequestContext).ToString()] = originalRequestContext;

            // Act by trying to extract info from ICaeAuthenticationProviderOption type
            AuthenticationProviderOption authProviderOption = httpRequestMessage.GetMsalAuthProviderOption();

            // Assert that we can still find the information
            Assert.Single(authProviderOption.Scopes);
            Assert.Equal("User.Read", authProviderOption.Scopes[0]);
            Assert.Equal("claim", authProviderOption.Claims);

        }
    }

    internal class CaeAuthProviderOptionTest : ICaeAuthenticationProviderOption
    {
        public string[] Scopes { get; set; }
        public string Claims { get; set; }
    }
}
