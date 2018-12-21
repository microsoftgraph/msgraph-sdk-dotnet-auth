using Microsoft.Identity.Client;

namespace Microsoft.Graph.Auth.Test.Mocks
{
    public class MockTokenCacheProvider : ITokenCacheProvider
    {
        private TokenCache cache;
        public MockTokenCacheProvider()
        {
            cache = new TokenCache();
        }
        public TokenCache GetTokenCacheInstance()
        {
            return cache;
        }
    }
}